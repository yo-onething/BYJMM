'use strict';
/**
 * Qsecret 桌面应用 —— Electron 主进程
 *
 * 这个壳刻意做得很薄：加密、鉴权、CSRF、防篡改全部仍在 server.js，
 * 窗口只是加载它在本机回环地址上的页面。壳自己只做四件事：
 *  1. 启动 / 关闭本地服务，并在退出前抹零内存密钥；
 *  2. 用加固过的 BrowserWindow 承载页面；
 *  3. 管理系统的「登录时自动启动」；
 *  4. 把旧版（后台服务方式安装的）数据复制到新的数据目录。
 *
 * 渲染进程的边界：
 *  - nodeIntegration 关闭、contextIsolation 开启、sandbox 开启、不注入 preload；
 *  - 只能在应用自己的 127.0.0.1 地址内导航，window.open 一律拒绝；
 *  - 权限：只对应用自身页面开放剪贴板读写，其余全部拒绝；
 *  - 会话 Cookie 放在纯内存分区，不写入磁盘；
 *  - 关闭窗口或退出应用时立即锁定保险库。
 */

const path = require('node:path');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');

const { app, BrowserWindow, Menu, session, dialog } = require('electron');
const { startServer } = require('../server.js');

const SELFTEST = process.argv.includes('--selftest');
// Windows 的登录项会带 --hidden 启动：不弹窗口，只在后台待命
const HIDDEN_LAUNCH = process.argv.includes('--hidden');
const IS_MAC = process.platform === 'darwin';

const PREFERRED_PORT = 7878;
const SESSION_PARTITION = 'qsecret';
const AUTOSTART_MARKER = 'autostart-initialized';

// ---------------------------------------------------------------- 数据目录

// 自检一律使用一次性的临时数据目录，绝不触碰真实保险库
if (SELFTEST) {
  app.setPath('userData', fs.mkdtempSync(path.join(os.tmpdir(), 'qsecret-selftest-')));
}

const USER_DATA_DIR = app.getPath('userData');
const DATA_DIR = path.join(USER_DATA_DIR, 'data');

/** 旧版用 service/install.command 安装时的数据位置（仅 macOS 存在这种安装）。 */
function legacyDataDir() {
  if (!IS_MAC) return null;
  return path.join(app.getPath('home'), 'Applications', 'Qsecret', 'data');
}

/**
 * 把旧版后台服务方式留下的保险库「复制」到新位置。
 * 只在目标位置还没有保险库时执行；旧文件原样保留，不做任何删除或移动。
 */
function migrateLegacyData(from = legacyDataDir(), to = DATA_DIR) {
  if (!from) return { copied: false, reason: 'no-legacy-location' };
  const source = path.join(from, 'vault.qvault');
  if (!fs.existsSync(source)) return { copied: false, reason: 'no-legacy-vault' };
  if (fs.existsSync(path.join(to, 'vault.qvault'))) return { copied: false, reason: 'already-exists' };

  const names = ['vault.qvault', 'vault.qvault.bak', 'auth-state.json'];
  const copied = [];
  fs.mkdirSync(to, { recursive: true, mode: 0o700 });
  for (const name of names) {
    const src = path.join(from, name);
    if (!fs.existsSync(src)) continue;
    fs.copyFileSync(src, path.join(to, name), fs.constants.COPYFILE_EXCL);
    fs.chmodSync(path.join(to, name), 0o600);
    copied.push(name);
  }
  return { copied: true, from, files: copied };
}

// ---------------------------------------------------------------- 日志

let logStream = null;

function log(line) {
  if (SELFTEST || !app.isPackaged) return console.log(line);
  try {
    if (!logStream) {
      logStream = fs.createWriteStream(path.join(app.getPath('logs'), 'qsecret.log'), {
        flags: 'a',
        mode: 0o600,
      });
      logStream.on('error', () => {
        logStream = null;
      });
    }
    logStream.write(`${line}\n`);
  } catch {
    /* 日志写不进去不影响使用 */
  }
}

function logPath() {
  try {
    return path.join(app.getPath('logs'), 'qsecret.log');
  } catch {
    return '（无法确定日志位置）';
  }
}

// ---------------------------------------------------------------- 登录时自动启动

/**
 * 交给 server.js 的自启钩子。设置页的开关通过本地接口调用这里，
 * 接口本身要求「已解锁 + CSRF 令牌」，和其它写操作一致。
 */
const autostart = {
  unavailableReason() {
    // macOS 只有位于「应用程序」文件夹里的应用才能可靠地注册为登录项；
    // 直接从安装镜像（DMG）里运行时注册，登录项会指向一个挂载后就消失的路径。
    if (IS_MAC && !app.isInApplicationsFolder()) {
      return '请先把 Qsecret 拖进「应用程序」文件夹，再开启登录时自动启动。';
    }
    return null;
  },
  get() {
    return !!app.getLoginItemSettings().openAtLogin;
  },
  set(enabled) {
    if (enabled) {
      const reason = this.unavailableReason();
      if (reason) throw new Error(reason);
    }
    app.setLoginItemSettings({
      openAtLogin: enabled,
      // Windows 登录项会把参数原样带回；macOS 用 wasOpenedAtLogin 判断
      args: process.platform === 'win32' ? ['--hidden'] : [],
    });
  },
};

/** 第一次正常运行时默认开启登录自启（之前的版本就是以后台服务方式随系统启动的）。 */
function enableAutostartOnFirstRun() {
  const marker = path.join(DATA_DIR, AUTOSTART_MARKER);
  if (fs.existsSync(marker)) return;
  const reason = autostart.unavailableReason();
  if (reason) {
    log(`未开启登录自启：${reason}`);
    return;
  }
  try {
    autostart.set(true);
    fs.writeFileSync(marker, new Date().toISOString(), { mode: 0o600 });
    log('首次运行：已开启「登录时自动启动」，可在设置中关闭');
  } catch (err) {
    log(`开启登录自启失败：${err && err.message ? err.message : err}`);
  }
}

// ---------------------------------------------------------------- 本地服务

let backend = null;
let origin = '';

function isPortFree(port) {
  return new Promise((resolve) => {
    const probe = net.createServer();
    probe.once('error', () => resolve(false));
    probe.listen(port, '127.0.0.1', () => probe.close(() => resolve(true)));
  });
}

/** 优先用固定端口（浏览器也能打开）；被占用时退让到系统分配的空闲端口。 */
async function pickPort(preferred) {
  return (await isPortFree(preferred)) ? preferred : 0;
}

async function startBackend() {
  const port = await pickPort(PREFERRED_PORT);
  backend = startServer({
    dataDir: DATA_DIR,
    port,
    desktop: true,
    autostart,
    log,
    standalone: false,
    onError: (err) => log(`本地服务错误：${err && err.message ? err.message : err}`),
  });
  await backend.ready;
  origin = `http://127.0.0.1:${backend.port}`;
}

function shutdownBackend() {
  // 锁定是同步的：清空会话并抹零内存中的密钥。HTTP 连接随进程一起结束。
  if (backend) backend.lock();
}

// ---------------------------------------------------------------- 窗口

let win = null;

function isOwnUrl(url) {
  return url === `${origin}/` || url.startsWith(`${origin}/`);
}

function createWindow() {
  if (win && !win.isDestroyed()) return win;

  win = new BrowserWindow({
    width: 1200,
    height: 780,
    minWidth: 760,
    minHeight: 540,
    show: false,
    backgroundColor: '#090c10',
    title: 'Qsecret',
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
      devTools: !app.isPackaged,
      partition: SESSION_PARTITION,
    },
  });

  win.once('ready-to-show', () => {
    if (!SELFTEST) win.show();
  });
  win.on('page-title-updated', (e) => e.preventDefault());
  win.on('close', shutdownBackend);
  win.on('closed', () => {
    win = null;
  });

  const wc = win.webContents;
  wc.setWindowOpenHandler(() => ({ action: 'deny' }));
  const guard = (e, url) => {
    if (!isOwnUrl(url)) e.preventDefault();
  };
  wc.on('will-navigate', guard);
  wc.on('will-redirect', guard);
  wc.on('render-process-gone', () => {
    shutdownBackend();
    if (win && !win.isDestroyed()) win.destroy();
  });

  win.loadURL(`${origin}/`);
  return win;
}

/** 用户主动打开应用（再次双击、点 Dock 图标）时：有窗口就带到前台，没有就新建。 */
function present() {
  if (!backend) return;
  if (win && !win.isDestroyed()) {
    if (win.isMinimized()) win.restore();
    win.show();
    win.focus();
    return;
  }
  createWindow();
}

function buildMenu() {
  const template = [
    ...(IS_MAC ? [{ role: 'appMenu' }] : []),
    ...(IS_MAC ? [{ role: 'fileMenu' }] : [{ role: 'quit', label: '退出 Qsecret' }]),
    // 编辑菜单必须保留：macOS 上复制 / 粘贴的快捷键依赖它
    { role: 'editMenu' },
    {
      label: '视图',
      submenu: [
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
      ],
    },
    { role: 'windowMenu' },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

/** 权限白名单：只有应用自身页面可以读写剪贴板（复制密码、45 秒后清除）。 */
function installPermissionPolicy() {
  const allowed = (webContents, permission) =>
    isOwnUrl(webContents.getURL()) &&
    (permission === 'clipboard-read' || permission === 'clipboard-sanitized-write');

  const ses = session.fromPartition(SESSION_PARTITION);
  ses.setPermissionRequestHandler((webContents, permission, callback) => {
    if (!allowed(webContents, permission)) {
      log(`已拒绝权限请求：${permission}`);
    }
    callback(allowed(webContents, permission));
  });
  ses.setPermissionCheckHandler((webContents, permission) => allowed(webContents, permission));
}

// ---------------------------------------------------------------- 自检
// 用法：Qsecret --selftest
// 在真实的安装包里跑一遍完整流程，结果以 JSON 输出，退出码 0 表示全部通过。
// 全程使用临时数据目录，结束后关闭服务并退出。

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitFor(fn, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await fn()) return true;
    if (Date.now() > deadline) throw new Error(`等待超时：${label}`);
    await sleep(100);
  }
}

async function runSelftest() {
  const results = [];
  const check = (name, ok, detail) => results.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) });

  const mainWin = createWindow();
  const js = (code) => mainWin.webContents.executeJavaScript(code, true);
  const loaded = new Promise((resolve) => mainWin.webContents.once('did-finish-load', resolve));
  await Promise.race([loaded, sleep(20000)]);
  await sleep(300);

  const step = async (name, fn) => {
    try {
      await fn();
    } catch (err) {
      check(name, false, `异常：${err && err.message ? err.message : err}`);
    }
  };

  await step('页面加载', async () => {
    const title = await js('document.title');
    check('页面加载', /Qsecret/.test(title), title);
    const bootHidden = await js(`document.getElementById('boot').classList.contains('hidden')`);
    check('启动遮罩已消失（本地服务已连通）', bootHidden === true, String(bootHidden));
    const authShown = await js(`!document.getElementById('auth').classList.contains('hidden')`);
    const authTitle = await js(`document.getElementById('authTitle').textContent`);
    check('首次运行进入「创建保险库」页', authShown === true && authTitle.includes('创建'), authTitle);
  });

  const MASTER = 'correct horse battery staple 42';
  await step('创建保险库', async () => {
    await js(`(function () {
      const p = document.getElementById('authPassword');
      const c = document.getElementById('authConfirm');
      p.value = ${JSON.stringify(MASTER)};
      c.value = ${JSON.stringify(MASTER)};
      p.dispatchEvent(new Event('input', { bubbles: true }));
      c.dispatchEvent(new Event('input', { bubbles: true }));
      document.getElementById('authForm').requestSubmit();
      return true;
    })()`);
    await waitFor(() => js(`!document.getElementById('app').classList.contains('hidden')`), 20000, '主界面出现');
    check('通过表单创建保险库并进入主界面', true);
  });

  let csrf = '';
  await step('会话与接口', async () => {
    const s = await js(`fetch('/api/session', { credentials: 'same-origin' }).then((r) => r.json())`);
    csrf = s.csrf || '';
    check('解锁后会话有效（Cookie + CSRF）', s.unlocked === true && csrf.length > 20);
    const st = await js(`fetch('/api/state', { credentials: 'same-origin' }).then((r) => r.json())`);
    check('状态接口报告桌面模式', st.desktop === true && st.service === false, JSON.stringify(st));
    const info = await js(`fetch('/api/app/autostart', { credentials: 'same-origin' }).then((r) => r.json())`);
    check('自启开关接口可读', typeof info.autoStart === 'boolean', JSON.stringify(info));
    const shown = await js(`(function () {
      const visible = (sel) => !document.querySelector(sel).classList.contains('hidden');
      return {
        manual: visible('#helpServiceDesktop'),
        webManualHidden: document.querySelector('#helpServiceWeb').classList.contains('hidden'),
        toggle: visible('#autostartRow'),
        mode: document.getElementById('helpMode').textContent,
        path: document.querySelector('.vault-path').textContent,
      };
    })()`);
    check(
      '界面按桌面应用显示：手册、自启开关、运行方式、数据路径',
      shown.manual && shown.webManualHidden && shown.toggle && shown.mode === '桌面应用' && shown.path.includes('Qsecret'),
      JSON.stringify(shown)
    );
    const status = await js(
      `fetch('/api/entries', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': ${JSON.stringify(csrf)} },
        body: JSON.stringify({ title: 'SELFTEST-ENTRY-TITLE', username: 'SELFTEST-USER', password: 'SELFTEST-PASSWORD-9f3a', url: 'https://example.invalid', category: 'login' }),
      }).then((r) => r.status)`
    );
    check('新增条目', status === 201, String(status));
    const listed = await js(`fetch('/api/entries', { credentials: 'same-origin' }).then((r) => r.json())`);
    check('条目可读回', listed.stats && listed.stats.total === 1, JSON.stringify(listed.stats));
  });

  await step('落盘为密文', async () => {
    const file = path.join(DATA_DIR, 'vault.qvault');
    const raw = fs.readFileSync(file, 'utf8');
    const leaks = ['SELFTEST-ENTRY-TITLE', 'SELFTEST-USER', 'SELFTEST-PASSWORD-9f3a', MASTER].filter((s) => raw.includes(s));
    check('保险库文件中搜不到标题 / 账号 / 密码 / 主密码明文', leaks.length === 0, leaks.join(', '));
    const mode = fs.statSync(file).mode & 0o777;
    check('保险库文件权限为 0600', mode === 0o600, mode.toString(8));
  });

  await step('锁定', async () => {
    shutdownBackend();
    const s = await js(`fetch('/api/session', { credentials: 'same-origin' }).then((r) => r.json())`);
    check('关闭窗口 / 退出时的锁定会让会话立即失效', s.unlocked === false, JSON.stringify(s));
    const back = await js(`(async () => {
      const r = await fetch('/api/vault/unlock', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: ${JSON.stringify(MASTER)} }) });
      return r.status;
    })()`);
    check('重新解锁成功', back === 200, String(back));
  });

  await step('窗口边界', async () => {
    const clip = await js(`navigator.clipboard.writeText('qsecret-selftest').then(() => 'ok', (e) => 'fail:' + e.name)`);
    check('应用页面可写剪贴板', clip === 'ok', clip);
    await js(`(function () { location.href = 'https://example.com/'; return true; })()`);
    await sleep(800);
    const url = mainWin.webContents.getURL();
    check('跳转到外部网址被拦截', isOwnUrl(url), url);
    const popped = await js(`(function () { const w = window.open('https://example.com/'); const blocked = !w; if (w) w.close(); return blocked; })()`);
    check('window.open 被拒绝', popped === true, String(popped));
    const nodeLeak = await js(`typeof window.require === 'undefined' && typeof window.process === 'undefined'`);
    check('页面拿不到 Node 接口', nodeLeak === true, String(nodeLeak));
  });

  await step('登录项', async () => {
    // 直接调用系统接口，绕过「必须在应用程序文件夹」的保护，只验证开关本身可写、可读、可清除
    app.setLoginItemSettings({ openAtLogin: true, args: process.platform === 'win32' ? ['--hidden'] : [] });
    const on = !!app.getLoginItemSettings().openAtLogin;
    check('可开启登录时自动启动', on === true);
  });

  await step('旧数据迁移', async () => {
    const legacy = fs.mkdtempSync(path.join(os.tmpdir(), 'qsecret-legacy-'));
    fs.writeFileSync(path.join(legacy, 'vault.qvault'), 'legacy-vault-bytes', { mode: 0o600 });
    fs.writeFileSync(path.join(legacy, 'leftover.txt'), 'x');
    const target = fs.mkdtempSync(path.join(os.tmpdir(), 'qsecret-migrated-'));
    const first = migrateLegacyData(legacy, target);
    const bytes = fs.readFileSync(path.join(target, 'vault.qvault'), 'utf8');
    check('旧保险库被复制到新数据目录', first.copied === true && bytes === 'legacy-vault-bytes', JSON.stringify(first));
    check('旧目录里的文件原样保留', fs.existsSync(path.join(legacy, 'vault.qvault')));
    fs.writeFileSync(path.join(target, 'vault.qvault'), 'newer-vault');
    const second = migrateLegacyData(legacy, target);
    const still = fs.readFileSync(path.join(target, 'vault.qvault'), 'utf8');
    check('新位置已有保险库时不覆盖', second.copied === false && still === 'newer-vault', JSON.stringify(second));
  });

  // 不管中间是否失败，都把登录项恢复为关闭，绝不留下指向临时路径的自启项
  try {
    app.setLoginItemSettings({ openAtLogin: false, args: [] });
    check('可关闭登录时自动启动', app.getLoginItemSettings().openAtLogin === false);
  } catch (err) {
    check('可关闭登录时自动启动', false, err && err.message);
  }

  const failed = results.filter((r) => !r.ok);
  const report = {
    ok: failed.length === 0,
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
    platform: `${process.platform} ${os.arch()}`,
    packaged: app.isPackaged,
    port: backend ? backend.port : null,
    passed: results.length - failed.length,
    failed: failed.length,
    results,
  };
  if (backend) await backend.close();
  return report;
}

// ---------------------------------------------------------------- 生命周期

// 整个应用所有渲染进程默认沙箱化
app.enableSandbox();
if (process.platform === 'win32') app.setAppUserModelId('io.github.yo-onething.qsecret');

if (!SELFTEST && !app.requestSingleInstanceLock()) {
  // 已经有一个 Qsecret 在运行：让那个实例把窗口拿到前台，自己退出
  app.quit();
} else {
  app.on('second-instance', present);

  app.on('activate', () => {
    // macOS：点 Dock 图标时若没有窗口则新建（登录自启后就是这种情况）
    if (backend && BrowserWindow.getAllWindows().length === 0) createWindow();
  });

  app.on('window-all-closed', () => {
    // Windows / Linux：关掉窗口即退出（退出时抹零密钥）；macOS 按惯例留在 Dock
    if (!IS_MAC) app.quit();
  });

  app.on('before-quit', shutdownBackend);
  app.on('quit', shutdownBackend);

  app.whenReady().then(async () => {
    try {
      const migrated = migrateLegacyData();
      if (migrated.copied) log(`已从旧版数据目录复制保险库：${migrated.from}（原文件保留）`);
      await startBackend();
    } catch (err) {
      const message = `本地服务启动失败：${err && err.message ? err.message : err}`;
      log(message);
      if (!SELFTEST) dialog.showErrorBox('Qsecret 无法启动', `${message}\n\n请重新打开应用。仍然失败请查看日志：\n${logPath()}`);
      app.exit(1);
      return;
    }

    installPermissionPolicy();
    buildMenu();

    if (SELFTEST) {
      runSelftest()
        .then((report) => {
          process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
          setTimeout(() => app.exit(report.ok ? 0 : 1), 200);
        })
        .catch((err) => {
          process.stdout.write(`${JSON.stringify({ ok: false, error: err && err.message ? err.message : String(err) })}\n`);
          setTimeout(() => app.exit(1), 200);
        });
      return;
    }

    // 登录时自启：只在后台待命，不弹窗口；用户下次打开应用时再出现
    const launchedAtLogin = IS_MAC ? !!app.getLoginItemSettings().wasOpenedAtLogin : HIDDEN_LAUNCH;
    if (!launchedAtLogin) createWindow();
    enableAutostartOnFirstRun();
  });
}
