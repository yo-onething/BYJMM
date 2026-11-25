'use strict';
/**
 * 内核自检：不依赖网络、不依赖真实数据，全部在临时目录完成。
 * 运行：node test/crypto.test.js
 */

const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { Vault, VaultError } = require('../lib/vault');

const PW = 'correct horse battery staple 42';
const PW2 = 'a-different-master-password-9';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qsecret-test-'));

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  \u2713 ${name}`);
    passed++;
  } catch (err) {
    console.error(`  \u2717 ${name}\n      ${err && err.message}`);
    failed++;
  }
}

function newVault(name) {
  const dir = path.join(root, name);
  fs.mkdirSync(dir, { recursive: true });
  return new Vault(dir);
}

function expectCode(fn, code) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof VaultError, `应抛 VaultError，实际: ${err}`);
    assert.strictEqual(err.code, code, `错误码应为 ${code}，实际 ${err.code}`);
    return;
  }
  throw new Error('预期抛出异常，但没有抛出');
}

console.log('\n[1] 创建与解锁');

const v1 = newVault('basic');
v1.create(PW);
v1.add({
  title: 'GitHub',
  username: 'alice@example.com',
  password: 'S3cret-Value-For-Test!',
  url: 'https://github.com',
  category: 'login',
  tags: ['工作'],
  notes: '恢复码在保险箱里',
});
v1.add({ title: '数据库', username: 'root', password: 'S3cret-Value-For-Test!', category: 'server' });

test('保险库文件已生成且权限为 0600', () => {
  assert.ok(fs.existsSync(v1.vaultPath));
  const mode = fs.statSync(v1.vaultPath).mode & 0o777;
  assert.strictEqual(mode, 0o600, `权限应为 600，实际 ${mode.toString(8)}`);
});

test('文件中不含任何明文条目字段', () => {
  const raw = fs.readFileSync(v1.vaultPath, 'utf8');
  for (const needle of ['GitHub', 'alice@example.com', 'S3cret-Value-For-Test', 'alice', '工作', '恢复码']) {
    assert.ok(!raw.includes(needle), `文件里出现了明文：${needle}`);
  }
});

test('正确主密码可解锁并读回全部字段', () => {
  const v = newVault('basic');
  v.unlock(PW);
  const list = v.list();
  assert.strictEqual(list.length, 2);
  const gh = list.find((e) => e.title === 'GitHub');
  assert.strictEqual(gh.username, 'alice@example.com');
  assert.strictEqual(gh.url, 'https://github.com');
  assert.deepStrictEqual(gh.tags, ['工作']);
  assert.strictEqual(gh.password, undefined, '列表接口不应返回密码');
  const full = v.get(gh.id, { reveal: true });
  assert.strictEqual(full.password, 'S3cret-Value-For-Test!');
  v.lock();
});

test('错误主密码被拒绝（BAD_PASSWORD）', () => {
  const v = newVault('basic');
  expectCode(() => v.unlock('wrong password wrong password'), 'BAD_PASSWORD');
  assert.strictEqual(v.unlocked, false, '失败后不应处于解锁状态');
});

console.log('\n[2] 防篡改');

test('修改任意密文字节后无法解锁（TAMPERED）', () => {
  const dir = path.join(root, 'tamper');
  fs.mkdirSync(dir, { recursive: true });
  const src = new Vault(dir);
  src.create(PW);
  src.add({ title: 'A', username: 'u', password: 'p', category: 'login' });
  src.lock();

  const raw = JSON.parse(fs.readFileSync(src.vaultPath, 'utf8'));
  const ct = Buffer.from(raw.entries[0].ct, 'base64');
  ct[0] ^= 0xff;
  raw.entries[0].ct = ct.toString('base64');
  fs.writeFileSync(src.vaultPath, JSON.stringify(raw), { mode: 0o600 });

  const v = new Vault(dir);
  expectCode(() => v.unlock(PW), 'TAMPERED');
});

test('删除一条密文记录会被文件封印发现（TAMPERED）', () => {
  const dir = path.join(root, 'drop');
  fs.mkdirSync(dir, { recursive: true });
  const src = new Vault(dir);
  src.create(PW);
  src.add({ title: 'A', username: 'u', password: 'p', category: 'login' });
  src.add({ title: 'B', username: 'u2', password: 'p2', category: 'login' });
  src.lock();

  const raw = JSON.parse(fs.readFileSync(src.vaultPath, 'utf8'));
  raw.entries.pop();
  fs.writeFileSync(src.vaultPath, JSON.stringify(raw), { mode: 0o600 });

  const v = new Vault(dir);
  expectCode(() => v.unlock(PW), 'TAMPERED');
});

test('篡改 KDF 参数（降低破解成本）会被拒绝', () => {
  const dir = path.join(root, 'kdf');
  fs.mkdirSync(dir, { recursive: true });
  const src = new Vault(dir);
  src.create(PW);
  src.lock();

  const raw = JSON.parse(fs.readFileSync(src.vaultPath, 'utf8'));
  raw.kdf.N = 1 << 14;
  fs.writeFileSync(src.vaultPath, JSON.stringify(raw), { mode: 0o600 });

  const v = new Vault(dir);
  // 参数被改后密钥不同，无法通过校验；无论报 BAD_PASSWORD 还是 TAMPERED 都必须拒绝
  try {
    v.unlock(PW);
  } catch (err) {
    assert.ok(err instanceof VaultError);
    assert.ok(['BAD_PASSWORD', 'TAMPERED'].includes(err.code), `实际错误码 ${err.code}`);
    return;
  }
  throw new Error('篡改 KDF 参数后仍然打开了保险库');
});

console.log('\n[3] 条目操作');

test('更新条目会递增版本号且保留创建时间', () => {
  const v = newVault('update');
  v.create(PW);
  const created = v.add({ title: '旧标题', username: 'u', password: 'p1', category: 'login' });
  v.update(created.id, { title: '新标题', password: 'p2' });
  const got = v.get(created.id, { reveal: true });
  assert.strictEqual(got.title, '新标题');
  assert.strictEqual(got.password, 'p2');
  assert.strictEqual(got.createdAt, created.createdAt);
  assert.strictEqual(got.rev, 2);
});

test('删除条目', () => {
  const v = newVault('delete');
  v.create(PW);
  const e = v.add({ title: 'X', username: 'u', password: 'p', category: 'note' });
  v.remove(e.id);
  assert.strictEqual(v.list().length, 0);
  expectCode(() => v.remove(e.id), 'NOT_FOUND');
});

test('非法输入被拒绝（空标题 / 超长字段）', () => {
  const v = newVault('validate');
  v.create(PW);
  expectCode(() => v.add({ title: '   ', password: 'p' }), 'VALIDATION');
  expectCode(() => v.add({ title: 'a'.repeat(201), password: 'p' }), 'VALIDATION');
});

test('重复密码与强度会被标记', () => {
  const v = newVault('stats');
  v.create(PW);
  v.add({ title: 'A', password: 'password123', category: 'login' });
  v.add({ title: 'B', password: 'password123', category: 'login' });
  const list = v.list();
  assert.ok(list.every((e) => e.reused === true));
  assert.ok(list.every((e) => e.strength < 60));
});

console.log('\n[4] 更换主密码');

test('更换后旧密码失效、新密码可读全部条目', () => {
  const dir = path.join(root, 'rotate');
  fs.mkdirSync(dir, { recursive: true });
  const v = new Vault(dir);
  v.create(PW);
  v.add({ title: 'A', username: 'u', password: 'p1', category: 'login' });
  v.changeMasterPassword(PW, PW2);
  const list = v.list();
  assert.strictEqual(list.length, 1);
  assert.strictEqual(v.get(list[0].id, { reveal: true }).password, 'p1');
  v.lock();

  const again = new Vault(dir);
  expectCode(() => again.unlock(PW), 'BAD_PASSWORD');
  again.unlock(PW2);
  assert.strictEqual(again.list().length, 1);
});

test('更换主密码时旧密码错误会被拒绝', () => {
  const v = newVault('rotate-wrong');
  v.create(PW);
  expectCode(() => v.changeMasterPassword('bad bad bad bad', PW2), 'BAD_PASSWORD');
});

console.log('\n[5] 备份与恢复');

test('备份文件可恢复（内容一致）', () => {
  const a = newVault('backup-a');
  a.create(PW);
  a.add({ title: 'A', username: 'u', password: 'p', category: 'login' });
  const bytes = a.exportBytes();
  a.lock();

  const b = newVault('backup-b');
  b.restoreFromBuffer(bytes, PW);
  assert.strictEqual(b.list().length, 1);
  assert.strictEqual(b.list()[0].title, 'A');
});

test('用错误密码恢复备份会被拒绝', () => {
  const a = newVault('backup-wrong-a');
  a.create(PW);
  const bytes = a.exportBytes();
  const b = newVault('backup-wrong-b');
  expectCode(() => b.restoreFromBuffer(bytes, 'nope-nope-nope'), 'BAD_PASSWORD');
});

test('恢复非法文件会被拒绝', () => {
  const v = newVault('backup-invalid');
  expectCode(() => v.restoreFromBuffer(Buffer.from('not a vault'), PW), 'NOT_A_VAULT');
});

console.log('\n[6] 设置');

test('自动锁定时间可保存并读回', () => {
  const v = newVault('settings');
  v.create(PW);
  assert.strictEqual(v.settings().idleMinutes, 5);
  v.saveSettings({ idleMinutes: 15 });
  assert.strictEqual(v.settings().idleMinutes, 15);
  v.saveSettings({ idleMinutes: 999 });
  assert.strictEqual(v.settings().idleMinutes, 15, '非法值应被忽略');
});

test('锁定后所有操作被拒绝', () => {
  const v = newVault('locked');
  v.create(PW);
  v.lock();
  expectCode(() => v.list(), 'LOCKED');
});

// 清理本次创建的临时目录（仅限本进程 mkdtemp 产物）
if (root.startsWith(os.tmpdir()) && path.basename(root).startsWith('qsecret-test-')) {
  fs.rmSync(root, { recursive: true, force: true });
}

console.log(`\n结果：${passed} 通过 / ${failed} 失败\n`);
process.exit(failed === 0 ? 0 : 1);