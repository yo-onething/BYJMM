'use strict';

// Node 18 是最低要求（crypto.hkdfSync / node:crypto 的 GCM 参数等）
const NODE_MAJOR = Number(process.versions.node.split('.')[0]);
if (NODE_MAJOR < 18) {
  console.error(`Qsecret 需要 Node.js 18 或更高版本，当前为 ${process.version}。`);
  console.error('请使用 start.command 启动（会自动挑选合适的 Node），或升级 Node。');
  process.exit(1);
}
/**
 * Qsecret 本地密码保险库 —— HTTP 服务
 *
 * 安全边界（务必保持）：
 *  - 只监听 127.0.0.1，不对外提供任何接口。
 *  - 校验 Host 头，阻断 DNS rebinding。
 *  - 会话 Cookie: HttpOnly + SameSite=Strict；密钥只在内存，锁定即抹零。
 *  - 所有写操作要求 X-CSRF-Token；校验 Origin / Sec-Fetch-Site。
 *  - 严格 CSP：无内联脚本、无外部资源、无 eval。
 *  - 解锁失败指数退避，状态落盘，重启无法绕过。
 *  - 不记录任何请求体、密码或条目内容。
 *
 * 两种运行方式共用本文件：
 *  - 命令行：node server.js（start.command / launchd 服务）
 *  - 桌面应用：desktop/main.js 通过 startServer() 加载，窗口就是它的界面
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const { Vault, VaultError } = require('./lib/vault');

const APP_DIR = __dirname;
const STATIC_DIR = path.join(APP_DIR, 'public');

const HOST = '127.0.0.1';
const DEFAULT_PORT = 7878;
// 由 launchd 等服务管理器拉起时置 1：端口被占时不退出，改为等待重试
const PORT_RETRY_MS = 10 * 1000;

const IDLE_SWEEP_MS = 10 * 1000;
const ABSOLUTE_TIMEOUT_MS = 8 * 60 * 60 * 1000;
const SESSION_COOKIE = 'qsid';
const MAX_BODY = 1024 * 1024;
const MAX_RESTORE_BODY = 64 * 1024 * 1024;

// 运行期状态：全部由 startServer() 填充。命令行与桌面应用共用同一套服务逻辑。
let DATA_DIR = null;
let PORT = DEFAULT_PORT;
let SERVICE_MODE = false;
// 桌面应用模式：多出「登录时自启」接口，并显示数据目录
let DESKTOP_MODE = false;
let autostartHook = null; // { get(), set(enabled), unavailableReason() }
let onError = null;
let logSink = null;

let vault = null;
let sessions = new Map(); // sid -> { csrf, createdAt, lastSeen }
let server = null;

function authStatePath() {
  return path.join(DATA_DIR, 'auth-state.json');
}

function autoStartInfo() {
  if (!autostartHook) return null;
  const reason = autostartHook.unavailableReason ? autostartHook.unavailableReason() : null;
  return { autoStart: !!autostartHook.get(), reason };
}

// ---------------------------------------------------------------- 失败退避

function readAuthState() {
  try {
    const raw = JSON.parse(fs.readFileSync(authStatePath(), 'utf8'));
    return {
      fails: Number(raw.fails) || 0,
      lockUntil: Number(raw.lockUntil) || 0,
    };
  } catch {
    return { fails: 0, lockUntil: 0 };
  }
}

function writeAuthState(state) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    const tmp = `${authStatePath()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600 });
    fs.renameSync(tmp, authStatePath());
  } catch {
    /* 状态写失败不阻断登录，但下次仍会重新计数 */
  }
}

function lockoutRemainingMs() {
  const st = readAuthState();
  return Math.max(0, st.lockUntil - Date.now());
}

/** 第 5 次失败起：60s, 120s, 240s ... 上限 1 小时。 */
function registerFailure() {
  const st = readAuthState();
  const fails = st.fails + 1;
  let lockUntil = 0;
  if (fails >= 5) {
    const step = Math.min(fails - 5, 10);
    lockUntil = Date.now() + Math.min(3600, 60 * Math.pow(2, step)) * 1000;
  }
  writeAuthState({ fails, lockUntil });
  return { fails, lockUntil };
}

function resetFailures() {
  writeAuthState({ fails: 0, lockUntil: 0 });
}

// ---------------------------------------------------------------- 会话

function createSession() {
  // 单会话模型：新解锁即失效旧会话，避免密钥在多处驻留。
  // 注意：这里只清会话表，不锁保险库——调用方刚完成解锁。
  sessions.clear();
  const sid = crypto.randomBytes(32).toString('base64url');
  const csrf = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  sessions.set(sid, { csrf, createdAt: now, lastSeen: now });
  return { sid, csrf };
}

function destroyAllSessions() {
  sessions.clear();
  if (vault.unlocked) vault.lock();
}

function currentSession(req) {
  const sid = parseCookies(req.headers.cookie || '')[SESSION_COOKIE];
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  const now = Date.now();
  if (now - s.createdAt > ABSOLUTE_TIMEOUT_MS) {
    destroyAllSessions();
    return null;
  }
  const idleMs = effectiveIdleMs();
  if (now - s.lastSeen > idleMs) {
    destroyAllSessions();
    return null;
  }
  s.lastSeen = now;
  return { sid, ...s };
}

function effectiveIdleMs() {
  let minutes = 5;
  if (vault.unlocked) {
    try {
      minutes = vault.settings().idleMinutes;
    } catch {
      minutes = 5;
    }
  }
  return minutes * 60 * 1000;
}

function parseCookies(header) {
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  return out;
}

// ---------------------------------------------------------------- HTTP 工具

function securityHeaders(res) {
  res.setHeader('Content-Security-Policy', [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
    "manifest-src 'self'",
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('Pragma', 'no-cache');
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
};

function sendJson(res, status, payload) {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
  });
  res.end(body);
}

function sendError(res, status, code, message) {
  sendJson(res, status, { error: { code, message } });
}

const ERROR_MAP = {
  LOCKED: [401, '保险库已锁定，请重新解锁'],
  BAD_PASSWORD: [401, '主密码错误'],
  WEAK_MASTER: [400, '主密码不符合要求'],
  VALIDATION: [400, '提交的内容不合法'],
  NOT_FOUND: [404, '条目不存在'],
  ALREADY_EXISTS: [409, '保险库已存在'],
  NO_VAULT: [404, '尚未创建保险库'],
  TAMPERED: [409, '保险库文件完整性校验失败，文件可能被修改'],
  CORRUPT: [409, '保险库文件已损坏'],
  NOT_A_VAULT: [400, '不是有效的 Qsecret 备份文件'],
  KDF_FAILED: [500, '密钥派生失败'],
};

function handleError(res, err) {
  if (err instanceof VaultError) {
    const [status, msg] = ERROR_MAP[err.code] || [400, '请求失败'];
    const message = err.detail ? `${msg}：${err.detail}` : msg;
    return sendError(res, status, err.code, message);
  }
  log(`内部错误: ${err && err.message ? err.message : err}`);
  return sendError(res, 500, 'INTERNAL', '服务内部错误');
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk) => {
      if (done) return;
      size += chunk.length;
      if (size > limit) {
        done = true;
        reject(new VaultError('VALIDATION', '请求体过大'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      resolve(Buffer.concat(chunks));
    });
    req.on('error', (err) => {
      if (done) return;
      done = true;
      reject(err);
    });
  });
}

async function readJson(req, limit = MAX_BODY) {
  const buf = await readBody(req, limit);
  if (buf.length === 0) return {};
  let data;
  try {
    data = JSON.parse(buf.toString('utf8'));
  } catch {
    throw new VaultError('VALIDATION', 'JSON 格式错误');
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new VaultError('VALIDATION', '请求体必须是对象');
  }
  return data;
}

function assertSameOrigin(req) {
  const host = String(req.headers.host || '');
  const allowed = new Set([`${HOST}:${PORT}`, `localhost:${PORT}`]);
  if (!allowed.has(host)) throw new VaultError('VALIDATION', '非法 Host');

  const origin = req.headers.origin;
  if (origin) {
    const ok = origin === `http://${host}`;
    if (!ok) throw new VaultError('VALIDATION', '跨站请求被拒绝');
  }
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') {
    throw new VaultError('VALIDATION', '跨站请求被拒绝');
  }
}

function assertCsrf(req, session) {
  const token = req.headers['x-csrf-token'];
  if (!token || typeof token !== 'string') throw new VaultError('VALIDATION', '缺少 CSRF 令牌');
  const a = Buffer.from(token);
  const b = Buffer.from(session.csrf);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    throw new VaultError('VALIDATION', 'CSRF 令牌无效');
  }
}

function serveStatic(res, pathname) {
  const map = {
    '/': 'index.html',
    '/index.html': 'index.html',
    '/app.js': 'app.js',
    '/theme.js': 'theme.js',
    '/style.css': 'style.css',
    '/favicon.svg': 'favicon.svg',
  };
  const file = map[pathname];
  if (!file) return false;

  const full = path.join(STATIC_DIR, file);
  let body;
  try {
    body = fs.readFileSync(full);
  } catch {
    return false;
  }
  const ext = path.extname(full);
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Content-Length': body.length,
  });
  res.end(body);
  return true;
}

function log(msg) {
  // 本地时间：日志是给使用者排障看的，UTC 时间戳容易误读
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  const ts = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} `
    + `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  const line = `[${ts}] ${msg}`;
  if (logSink && logSink !== log) return logSink(line);
  process.stdout.write(`${line}\n`);
}

// ---------------------------------------------------------------- 密码生成

function generatePassword(opts = {}) {
  const length = Math.min(128, Math.max(8, Number(opts.length) || 20));
  const upper = opts.upper !== false;
  const lower = opts.lower !== false;
  const digits = opts.digits !== false;
  const symbols = opts.symbols !== false;
  const avoidAmbiguous = opts.avoidAmbiguous !== false;

  let sets = [];
  if (lower) sets.push('abcdefghijkmnopqrstuvwxyz' + (avoidAmbiguous ? '' : 'l'));
  if (upper) sets.push('ABCDEFGHJKLMNPQRSTUVWXYZ' + (avoidAmbiguous ? '' : 'I'));
  if (digits) sets.push('23456789' + (avoidAmbiguous ? '' : '01'));
  if (symbols) sets.push('!@#$%^&*()-_=+[]{};:,.?/');

  if (sets.length === 0) sets = ['abcdefghijkmnopqrstuvwxyz'];

  const all = sets.join('');
  const chars = [];
  // 每类至少一个，保证实际可用性
  for (const set of sets) {
    if (chars.length >= length) break;
    chars.push(set[crypto.randomInt(set.length)]);
  }
  while (chars.length < length) chars.push(all[crypto.randomInt(all.length)]);

  // Fisher–Yates，随机源为 crypto.randomInt
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}

// ---------------------------------------------------------------- 路由

async function handleApi(req, res, url) {
  const { pathname } = url;
  const method = req.method || 'GET';

  assertSameOrigin(req);

  // ---- 无需会话的接口
  if (pathname === '/api/state' && method === 'GET') {
    const remaining = lockoutRemainingMs();
    return sendJson(res, 200, {
      hasVault: vault.exists(),
      unlocked: vault.unlocked,
      idleMinutes: vault.unlocked ? safeSettings().idleMinutes : null,
      lockoutSeconds: Math.ceil(remaining / 1000),
      service: SERVICE_MODE,
      desktop: DESKTOP_MODE,
      autoStart: DESKTOP_MODE ? (autoStartInfo()?.autoStart ?? null) : null,
      platform: DESKTOP_MODE ? process.platform : undefined,
      version: 1,
    });
  }

  // 会话探测：未登录也返回 200，避免无意义的 401 噪音；不含任何敏感数据
  if (pathname === '/api/session' && method === 'GET') {
    const s = currentSession(req);
    if (!s || !vault.unlocked) {
      return sendJson(res, 200, { unlocked: false });
    }
    return sendJson(res, 200, {
      unlocked: true,
      csrf: s.csrf,
      idleMinutes: safeSettings().idleMinutes,
      absoluteExpiresAt: s.createdAt + ABSOLUTE_TIMEOUT_MS,
      // 数据目录只在已解锁后可见，界面用它显示真实的保险库位置
      dataDir: DESKTOP_MODE ? DATA_DIR : undefined,
    });
  }

  if (pathname === '/api/vault/create' && method === 'POST') {
    const body = await readJson(req);
    const password = String(body.password || '');
    const confirm = String(body.confirm || '');
    if (password !== confirm) throw new VaultError('VALIDATION', '两次输入的主密码不一致');
    if (lockoutRemainingMs() > 0) return rateLimited(res);
    if (vault.exists()) throw new VaultError('ALREADY_EXISTS');

    vault.create(password);
    const { sid, csrf } = createSession();
    setSessionCookie(res, sid);
    resetFailures();
    log('已创建新保险库');
    return sendJson(res, 201, { csrf, unlocked: true });
  }

  if (pathname === '/api/vault/unlock' && method === 'POST') {
    const body = await readJson(req);
    if (lockoutRemainingMs() > 0) return rateLimited(res);

    try {
      vault.unlock(String(body.password || ''));
    } catch (err) {
      if (err instanceof VaultError && err.code === 'BAD_PASSWORD') {
        const { fails, lockUntil } = registerFailure();
        const wait = Math.max(0, Math.ceil((lockUntil - Date.now()) / 1000));
        log(`解锁失败（累计 ${fails} 次）`);
        return sendJson(res, 401, {
          error: {
            code: 'BAD_PASSWORD',
            message: wait > 0 ? `主密码错误，请等待 ${wait} 秒后再试` : '主密码错误',
          },
          fails,
          lockoutSeconds: wait,
        });
      }
      throw err;
    }

    const { sid, csrf } = createSession();
    setSessionCookie(res, sid);
    resetFailures();
    log('保险库已解锁');
    return sendJson(res, 200, { csrf, unlocked: true });
  }

  // ---- 以下都需要有效会话
  const session = currentSession(req);
  if (!session) {
    if (vault.unlocked) destroyAllSessions();
    return sendError(res, 401, 'LOCKED', '请先解锁保险库');
  }
  if (!vault.unlocked) {
    destroyAllSessions();
    return sendError(res, 401, 'LOCKED', '请先解锁保险库');
  }

  if (method !== 'GET') assertCsrf(req, session);

  if (pathname === '/api/vault/lock' && method === 'POST') {
    destroyAllSessions();
    clearSessionCookie(res);
    log('已手动锁定');
    return sendJson(res, 200, { locked: true });
  }

  if (pathname === '/api/entries' && method === 'GET') {
    const entries = vault.list();
    const stats = {
      total: entries.length,
      weak: entries.filter((e) => e.strength < 60).length,
      reused: entries.filter((e) => e.reused).length,
      categories: entries.reduce((acc, e) => {
        acc[e.category] = (acc[e.category] || 0) + 1;
        return acc;
      }, {}),
    };
    return sendJson(res, 200, { entries, stats });
  }

  if (pathname === '/api/entries' && method === 'POST') {
    const body = await readJson(req);
    const entry = vault.add(body);
    return sendJson(res, 201, { entry });
  }

  const revealMatch = pathname.match(/^\/api\/entries\/([0-9a-f-]{36})\/reveal$/);
  if (revealMatch && method === 'POST') {
    const entry = vault.get(revealMatch[1], { reveal: true });
    return sendJson(res, 200, { id: entry.id, password: entry.password });
  }

  const itemMatch = pathname.match(/^\/api\/entries\/([0-9a-f-]{36})$/);
  if (itemMatch) {
    const id = itemMatch[1];
    if (method === 'GET') return sendJson(res, 200, { entry: vault.get(id) });
    if (method === 'PUT') {
      const body = await readJson(req);
      const entry = vault.update(id, body);
      return sendJson(res, 200, { entry });
    }
    if (method === 'DELETE') {
      vault.remove(id);
      return sendJson(res, 200, { deleted: true });
    }
  }

  if (pathname === '/api/generate' && method === 'POST') {
    const body = await readJson(req);
    const password = generatePassword(body);
    return sendJson(res, 200, { password });
  }

  if (pathname === '/api/settings') {
    if (method === 'GET') return sendJson(res, 200, { settings: safeSettings() });
    if (method === 'PUT') {
      const body = await readJson(req);
      const settings = vault.saveSettings(body);
      return sendJson(res, 200, { settings });
    }
  }

  if (pathname === '/api/master/change' && method === 'POST') {
    const body = await readJson(req);
    const current = String(body.currentPassword || '');
    const next = String(body.newPassword || '');
    if (next.length < 12) throw new VaultError('WEAK_MASTER', '主密码至少 12 位');
    vault.changeMasterPassword(current, next);
    // 换钥后旧会话密钥已作废，重新下发会话（createSession 会清空旧会话表）
    resetFailures();
    const { sid, csrf } = createSession();
    setSessionCookie(res, sid);
    log('主密码已更新，全部条目已重新加密');
    return sendJson(res, 200, { csrf, unlocked: true });
  }

  if (pathname === '/api/backup' && method === 'GET') {
    const bytes = vault.exportBytes();
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="qsecret-backup-${new Date()
        .toISOString()
        .slice(0, 10)}.qvault"`,
      'Content-Length': bytes.length,
    });
    return res.end(bytes);
  }

  // 「登录系统时自动启动」开关：仅桌面应用提供，且必须已解锁 + 带 CSRF 令牌
  if (pathname === '/api/app/autostart' && DESKTOP_MODE && autostartHook) {
    if (method === 'GET') return sendJson(res, 200, autoStartInfo());
    if (method === 'PUT') {
      const body = await readJson(req);
      const enabled = body.enabled;
      if (typeof enabled !== 'boolean') throw new VaultError('VALIDATION', 'enabled 必须是布尔值');
      const reason = autostartHook.unavailableReason ? autostartHook.unavailableReason() : null;
      if (reason) return sendError(res, 409, 'AUTOSTART_UNAVAILABLE', reason);
      try {
        autostartHook.set(enabled);
      } catch (err) {
        return sendError(res, 500, 'AUTOSTART_FAILED', `设置开机自启失败：${err && err.message ? err.message : err}`);
      }
      log(`登录时自动启动：${enabled ? '开启' : '关闭'}`);
      return sendJson(res, 200, autoStartInfo());
    }
  }

  if (pathname === '/api/backup/restore' && method === 'POST') {
    const body = await readJson(req, MAX_RESTORE_BODY);
    const password = String(body.password || '');
    const data = String(body.data || '');
    if (!data) throw new VaultError('VALIDATION', '缺少备份内容');
    const buf = Buffer.from(data, 'base64');
    vault.restoreFromBuffer(buf, password);
    // 恢复后密钥已换成备份文件的密钥，重新下发会话
    const { sid, csrf } = createSession();
    setSessionCookie(res, sid);
    log('已从备份恢复保险库');
    return sendJson(res, 200, { csrf, unlocked: true, restored: true });
  }

  return sendError(res, 404, 'NOT_FOUND', '接口不存在');
}

function rateLimited(res) {
  const wait = Math.max(1, Math.ceil(lockoutRemainingMs() / 1000));
  res.setHeader('Retry-After', String(wait));
  return sendError(res, 429, 'RATE_LIMITED', `尝试过于频繁，请等待 ${wait} 秒后再试`);
}

function safeSettings() {
  try {
    return vault.settings();
  } catch {
    return { idleMinutes: 5 };
  }
}

function setSessionCookie(res, sid) {
  res.setHeader(
    'Set-Cookie',
    `${SESSION_COOKIE}=${sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(
      ABSOLUTE_TIMEOUT_MS / 1000
    )}`
  );
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
}

// ---------------------------------------------------------------- 入口

function createRequestHandler() {
  return async (req, res) => {
    securityHeaders(res);

    let url;
    try {
      url = new URL(req.url, `http://${req.headers.host || `${HOST}:${PORT}`}`);
    } catch {
      return sendError(res, 400, 'VALIDATION', '非法请求地址');
    }

    if (req.method === 'GET' && url.pathname.startsWith('/api/') === false) {
      if (serveStatic(res, url.pathname)) return;
      return sendError(res, 404, 'NOT_FOUND', '页面不存在');
    }

    try {
      await handleApi(req, res, url);
    } catch (err) {
      if (res.headersSent) return res.end();
      handleError(res, err);
    }
  };
}

/**
 * 启动服务。命令行直接运行本文件、以及桌面应用（Electron）都走这里。
 *
 * options:
 *   dataDir      数据目录；缺省读 QSECRET_DATA，再缺省为应用目录下 data/
 *   port         监听端口；缺省读 QSECRET_PORT，再缺省 7878。传 0 表示随机空闲端口
 *   serviceMode  服务管理器模式（端口被占时等待接管）
 *   desktop      桌面应用模式（开放自启接口、显示数据目录）
 *   autostart    { get(), set(enabled), unavailableReason() } —— desktop 模式下由壳注入
 *   log          日志函数，缺省写 stdout
 *   onError      监听失败时的回调；缺省按命令行语义退出进程
 *   standalone   是否接管进程信号与未捕获异常，缺省 true
 */
function startServer(options = {}) {
  if (server) throw new Error('服务已经启动，不能重复调用 startServer');

  DATA_DIR = options.dataDir
    ? path.resolve(options.dataDir)
    : process.env.QSECRET_DATA
      ? path.resolve(process.env.QSECRET_DATA)
      : path.join(APP_DIR, 'data');

  const wantedPort = options.port != null ? Number(options.port) : Number(process.env.QSECRET_PORT || DEFAULT_PORT);
  PORT = Number.isInteger(wantedPort) && wantedPort >= 0 && wantedPort <= 65535 ? wantedPort : DEFAULT_PORT;
  SERVICE_MODE = options.serviceMode != null ? !!options.serviceMode : process.env.QSECRET_SERVICE === '1';
  DESKTOP_MODE = !!options.desktop;
  autostartHook = options.autostart || null;
  onError = typeof options.onError === 'function' ? options.onError : null;
  logSink = typeof options.log === 'function' ? options.log : null;
  const standalone = options.standalone !== false;

  vault = new Vault(DATA_DIR);
  sessions = new Map();

  server = http.createServer(createRequestHandler());

  // 监听成功 / 失败的通知，供桌面壳决定何时打开窗口
  let markReady;
  const ready = new Promise((resolve, reject) => {
    markReady = { resolve, reject };
  });
  // 命令行 / 服务模式下没有人 await：先挂一个空分支，避免 reject 变成未处理的拒绝而让进程崩溃
  ready.catch(() => {});

  const sweeper = setInterval(() => {
    if (sessions.size === 0) return;
    const now = Date.now();
    const idleMs = effectiveIdleMs();
    let expired = false;
    for (const s of sessions.values()) {
      if (now - s.lastSeen > idleMs || now - s.createdAt > ABSOLUTE_TIMEOUT_MS) expired = true;
    }
    if (expired) {
      log('会话空闲超时，已自动锁定');
      destroyAllSessions();
    }
  }, IDLE_SWEEP_MS);
  sweeper.unref();

  server.on('error', (err) => {
    if (err && err.code === 'EADDRINUSE') {
      log(`端口 ${PORT} 已被占用——可能已有一个 Qsecret 在运行`);
      markReady.reject(err);
      if (onError) return onError(err);
      if (SERVICE_MODE) {
        // 后台服务不与手动启动的实例抢端口；对方退出后再接管
        // 该定时器必须保持引用，否则事件循环为空会导致进程静默退出
        setTimeout(() => server.listen(PORT, HOST), PORT_RETRY_MS);
        return;
      }
      process.exit(0);
    }
    log(`服务启动失败：${err && err.message ? err.message : err}`);
    markReady.reject(err);
    if (onError) return onError(err);
    process.exit(1);
  });

  server.on('clientError', (err, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  });

  server.headersTimeout = 15 * 1000;
  server.requestTimeout = 30 * 1000;
  server.keepAliveTimeout = 10 * 1000;

  server.listen(PORT, HOST, () => {
    // 传 0 时拿到系统分配的实际端口，Host 校验要用真实值
    PORT = server.address().port;
    fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
    log(`Qsecret 已启动  →  http://${HOST}:${PORT}${SERVICE_MODE ? '（后台服务模式）' : ''}`);
    log(`数据目录：${DATA_DIR}`);
    log(`保险库：${vault.exists() ? '已存在' : '尚未创建（首次打开会引导创建）'}`);
    markReady.resolve();
  });

  function shutdown() {
    log('正在退出，抹零内存密钥…');
    destroyAllSessions();
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 500).unref();
  }

  if (standalone) {
    process.on('uncaughtException', (err) => {
      log(`未捕获异常: ${err && err.message ? err.message : err}`);
    });
    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);
  }

  return {
    server,
    /** 监听成功时 resolve；失败时 reject（之后仍会按 onError / 退出语义处理）。 */
    ready,
    get port() {
      return PORT;
    },
    dataDir: DATA_DIR,
    /** 立即锁定：清空全部会话并抹零内存中的密钥。 */
    lock() {
      destroyAllSessions();
    },
    async close() {
      clearInterval(sweeper);
      destroyAllSessions();
      await new Promise((resolve) => {
        server.close(() => {
          server = null;
          resolve();
        });
        if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
      });
    },
  };
}

module.exports = { startServer };

if (require.main === module) {
  startServer();
}