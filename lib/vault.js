'use strict';
/**
 * 保险库存储层：单文件、全密文、原子写入。
 *
 * 文件里没有任何明文条目字段；除了 KDF 参数、盐、版本号（这些本来就需要公开）
 * 之外，标题、账号、密码、备注全部是 AES-GCM 密文。
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const C = require('./crypto');

const CATEGORIES = ['login', 'card', 'server', 'note', 'other'];

const LIMITS = {
  title: 200,
  username: 200,
  password: 1024,
  url: 2048,
  notes: 20000,
  tags: 20,
  tag: 40,
};

class VaultError extends Error {
  constructor(code, detail) {
    super(code);
    this.code = code;
    this.detail = detail;
  }
}

function nowIso() {
  return new Date().toISOString();
}

function clampStr(value, max, field) {
  if (value == null) return '';
  if (typeof value !== 'string') throw new VaultError('VALIDATION', `${field} 必须是字符串`);
  const v = value.replace(/\u0000/g, '');
  if (v.length > max) throw new VaultError('VALIDATION', `${field} 超出长度限制（${max}）`);
  return v;
}

function normalizeEntry(input, base) {
  const src = input || {};
  const cat = CATEGORIES.includes(src.category) ? src.category : (base ? base.category : 'other');
  const tags = Array.isArray(src.tags)
    ? src.tags
        .map((t) => clampStr(t, LIMITS.tag, 'tag').trim())
        .filter(Boolean)
        .slice(0, LIMITS.tags)
    : base
      ? base.tags
      : [];

  const entry = {
    title: clampStr(src.title, LIMITS.title, '标题').trim(),
    username: clampStr(src.username, LIMITS.username, '账号'),
    password: clampStr(src.password, LIMITS.password, '密码'),
    url: clampStr(src.url, LIMITS.url, '网址').trim(),
    notes: clampStr(src.notes, LIMITS.notes, '备注'),
    category: cat,
    tags,
    createdAt: base ? base.createdAt : nowIso(),
    updatedAt: nowIso(),
  };

  if (!entry.title) throw new VaultError('VALIDATION', '标题不能为空');
  return entry;
}

/** 粗略强度评估，仅用于提醒，不参与任何安全判断。 */
function strengthOf(pw) {
  if (!pw) return 0;
  let score = Math.min(60, pw.length * 4);
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  score += classes * 10;
  if (/^(.)\1+$/.test(pw)) score -= 40;
  if (/^[0-9]+$/.test(pw)) score -= 25;
  if (/^(password|qwerty|admin|123456|letmein|iloveyou)/i.test(pw)) score -= 40;
  return Math.max(0, Math.min(100, score));
}

class Vault {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.vaultPath = path.join(dataDir, 'vault.qvault');
    this.backupPath = path.join(dataDir, 'vault.qvault.bak');
    this.data = null;
    this.keys = null;
    this.salt = null;
  }

  get unlocked() {
    return !!(this.keys && this.data);
  }

  exists() {
    return fs.existsSync(this.vaultPath);
  }

  /** 首次创建：生成盐、派生密钥、写入空保险库。 */
  create(masterPassword) {
    assertPasswordStrength(masterPassword);
    ensureDir(this.dataDir);
    if (this.exists()) throw new VaultError('ALREADY_EXISTS');

    const { header, keys, salt } = C.createHeader(masterPassword);
    this.data = header;
    this.keys = keys;
    this.salt = salt;
    this.persist({ backup: false });
    return this;
  }

  /** 解锁：读取文件 -> 校验哨兵 -> 校验文件封印。 */
  unlock(masterPassword) {
    if (!this.exists()) throw new VaultError('NO_VAULT');
    const raw = fs.readFileSync(this.vaultPath, 'utf8');
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      throw new VaultError('CORRUPT');
    }
    if (!data || data.format !== C.FORMAT || data.version !== C.VERSION) {
      throw new VaultError('NOT_A_VAULT');
    }
    if (!C.validateKdf(data.kdf)) throw new VaultError('CORRUPT');

    let result;
    try {
      result = C.unlockHeader(data, masterPassword);
    } catch (err) {
      if (err.code === 'BAD_PASSWORD') throw new VaultError('BAD_PASSWORD');
      if (err.code === 'TAMPERED') throw new VaultError('TAMPERED');
      if (err.code === 'KDF_FAILED') throw new VaultError('KDF_FAILED');
      throw new VaultError('CORRUPT');
    }

    if (this.keys) this.keys.wipe();
    this.data = data;
    this.keys = result.keys;
    this.salt = result.salt;
    return this;
  }

  lock() {
    if (this.keys && typeof this.keys.wipe === 'function') this.keys.wipe();
    this.keys = null;
    this.data = null;
    this.salt = null;
  }

  requireUnlocked() {
    if (!this.unlocked) throw new VaultError('LOCKED');
  }

  /** 原子写入：临时文件 + fsync + rename，并保留上一版 .bak。 */
  persist({ backup = true } = {}) {
    this.requireUnlocked();
    ensureDir(this.dataDir);
    this.data.revision = (this.data.revision || 0) + 1;
    this.data.updatedAt = nowIso();
    this.data.mac = C.fileMac(this.keys.macKey, this.data);

    const json = JSON.stringify(this.data, null, 2);
    const tmp = path.join(this.dataDir, `.vault.${process.pid}.${Date.now()}.tmp`);

    const fd = fs.openSync(tmp, 'w', 0o600);
    try {
      fs.writeFileSync(fd, json, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    if (backup && this.exists()) {
      try {
        fs.copyFileSync(this.vaultPath, this.backupPath);
        fs.chmodSync(this.backupPath, 0o600);
      } catch {
        /* 备份失败不阻断主写入 */
      }
    }
    fs.renameSync(tmp, this.vaultPath);
    fs.chmodSync(this.vaultPath, 0o600);
    try {
      const dfd = fs.openSync(this.dataDir, 'r');
      fs.fsyncSync(dfd);
      fs.closeSync(dfd);
    } catch {
      /* 目录 fsync 在部分文件系统不可用 */
    }
  }

  _entryAad(rec) {
    return C.aadEntry(this.data.vaultId, rec.id, rec.rev);
  }

  _decryptRecord(rec) {
    let buf;
    try {
      buf = C.open(this.keys.encKey, rec, this._entryAad(rec));
    } catch {
      throw new VaultError('CORRUPT');
    }
    try {
      return JSON.parse(buf.toString('utf8'));
    } catch {
      throw new VaultError('CORRUPT');
    } finally {
      buf.fill(0);
    }
  }

  _sealEntry(id, rev, entry) {
    const box = C.seal(this.keys.encKey, JSON.stringify(entry), C.aadEntry(this.data.vaultId, id, rev));
    return { id, rev, n: box.n, ct: box.ct, tag: box.tag };
  }

  /** 解密全部条目（不返回密码），供列表/搜索使用。 */
  list() {
    this.requireUnlocked();
    const all = this.data.entries.map((rec) => {
      const e = this._decryptRecord(rec);
      return { ...e, id: rec.id, rev: rec.rev };
    });

    const counts = new Map();
    for (const e of all) counts.set(e.password, (counts.get(e.password) || 0) + 1);

    return all
      .map((e) => ({
        id: e.id,
        rev: e.rev,
        title: e.title,
        username: e.username,
        url: e.url,
        category: e.category,
        tags: e.tags,
        notes: e.notes,
        createdAt: e.createdAt,
        updatedAt: e.updatedAt,
        strength: strengthOf(e.password),
        reused: e.password ? counts.get(e.password) > 1 : false,
      }))
      .sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0));
  }

  /** 取单条，reveal=true 时返回明文密码。 */
  get(id, { reveal = false } = {}) {
    this.requireUnlocked();
    const rec = this.data.entries.find((r) => r.id === id);
    if (!rec) throw new VaultError('NOT_FOUND');
    const e = this._decryptRecord(rec);
    const out = { ...e, id: rec.id, rev: rec.rev, strength: strengthOf(e.password) };
    if (!reveal) delete out.password;
    return out;
  }

  add(input) {
    this.requireUnlocked();
    const entry = normalizeEntry(input, null);
    const id = C.uuid();
    const rec = this._sealEntry(id, 1, entry);
    this.data.entries.push(rec);
    this.persist();
    return { id, rev: 1, ...entry };
  }

  update(id, input) {
    this.requireUnlocked();
    const idx = this.data.entries.findIndex((r) => r.id === id);
    if (idx < 0) throw new VaultError('NOT_FOUND');
    const current = this._decryptRecord(this.data.entries[idx]);
    const merged = normalizeEntry({ ...current, ...input }, current);
    const nextRev = this.data.entries[idx].rev + 1;
    this.data.entries[idx] = this._sealEntry(id, nextRev, merged);
    this.persist();
    return { id, rev: nextRev, ...merged };
  }

  remove(id) {
    this.requireUnlocked();
    const before = this.data.entries.length;
    this.data.entries = this.data.entries.filter((r) => r.id !== id);
    if (this.data.entries.length === before) throw new VaultError('NOT_FOUND');
    this.persist();
  }

  settings() {
    this.requireUnlocked();
    try {
      const buf = C.open(this.keys.encKey, this.data.meta, C.aadMeta(this.data.vaultId));
      const meta = JSON.parse(buf.toString('utf8'));
      buf.fill(0);
      return { idleMinutes: Number(meta?.settings?.idleMinutes) || 5 };
    } catch {
      return { idleMinutes: 5 };
    }
  }

  saveSettings(partial) {
    this.requireUnlocked();
    const current = this.settings();
    const idle = Number(partial?.idleMinutes);
    const idleMinutes = [1, 5, 15, 30, 60].includes(idle) ? idle : current.idleMinutes;
    const payload = JSON.stringify({ settings: { idleMinutes } });
    this.data.meta = C.seal(this.keys.encKey, payload, C.aadMeta(this.data.vaultId));
    this.persist();
    return { idleMinutes };
  }

  /** 修改主密码：用旧密码验证，生成新盐，全量重新加密。 */
  changeMasterPassword(oldPassword, newPassword) {
    this.requireUnlocked();
    assertPasswordStrength(newPassword);

    // 重新校验旧密码（防止会话被劫持后直接改密码）
    let check;
    try {
      check = C.unlockHeader(this.data, oldPassword);
    } catch (err) {
      throw new VaultError(err.code === 'TAMPERED' ? 'TAMPERED' : 'BAD_PASSWORD');
    }
    check.keys.wipe();

    const salt = C.newSalt();
    const newKeys = C.deriveKeys(newPassword, salt, C.KDF_DEFAULT);

    // 旧钥解密 -> 新钥加密，逐条处理，任何一条失败则整体中止
    const rebuilt = this.data.entries.map((rec) => {
      const entry = this._decryptRecord(rec);
      const nextRev = rec.rev + 1;
      const box = C.seal(
        newKeys.encKey,
        JSON.stringify(entry),
        C.aadEntry(this.data.vaultId, rec.id, nextRev)
      );
      return { id: rec.id, rev: nextRev, n: box.n, ct: box.ct, tag: box.tag };
    });

    const meta = this.settings();
    const newMeta = C.seal(
      newKeys.encKey,
      JSON.stringify({ settings: meta }),
      C.aadMeta(this.data.vaultId)
    );

    const oldKeys = this.keys;
    this.data.kdf = {
      algo: 'scrypt',
      N: C.KDF_DEFAULT.N,
      r: C.KDF_DEFAULT.r,
      p: C.KDF_DEFAULT.p,
      salt: C.b64(salt),
    };
    this.data.verifier = C.seal(
      newKeys.verKey,
      Buffer.from('qsecret:verifier:v1', 'utf8'),
      C.aadVerifier(this.data.vaultId)
    );
    this.data.entries = rebuilt;
    this.data.meta = newMeta;

    this.keys = newKeys;
    this.salt = salt;
    oldKeys.wipe();
    this.persist();
  }

  /** 导出的是已经加密的完整文件，泄露导出物不等于泄露明文。 */
  exportBytes() {
    this.requireUnlocked();
    this.persist();
    return fs.readFileSync(this.vaultPath);
  }

  /**
   * 从备份恢复：要求备份文件本身能被其主密码解开（证明是合法 Qsecret 文件），
   * 然后覆盖当前文件并切换会话密钥。
   */
  restoreFromBuffer(buffer, password) {
    if (!Buffer.isBuffer(buffer) || buffer.length > 32 * 1024 * 1024) {
      throw new VaultError('VALIDATION', '备份文件过大或无效');
    }
    let data;
    try {
      data = JSON.parse(buffer.toString('utf8'));
    } catch {
      throw new VaultError('NOT_A_VAULT');
    }
    if (!data || data.format !== C.FORMAT || data.version !== C.VERSION) {
      throw new VaultError('NOT_A_VAULT');
    }
    if (!C.validateKdf(data.kdf)) throw new VaultError('CORRUPT');

    let result;
    try {
      result = C.unlockHeader(data, password);
    } catch (err) {
      throw new VaultError(err.code === 'TAMPERED' ? 'TAMPERED' : 'BAD_PASSWORD');
    }

    if (this.keys) this.keys.wipe();
    if (this.exists()) {
      try {
        fs.copyFileSync(this.vaultPath, this.backupPath);
        fs.chmodSync(this.backupPath, 0o600);
      } catch {
        /* ignore */
      }
    }
    ensureDir(this.dataDir);
    const tmp = path.join(this.dataDir, `.restore.${process.pid}.${Date.now()}.tmp`);
    fs.writeFileSync(tmp, buffer, { mode: 0o600 });
    fs.renameSync(tmp, this.vaultPath);
    fs.chmodSync(this.vaultPath, 0o600);

    this.data = data;
    this.keys = result.keys;
    this.salt = result.salt;
    return this;
  }
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    fs.chmodSync(dir, 0o700);
  } catch {
    /* ignore */
  }
}

/** 主密码最低要求：12 位以上。这是唯一能保护全部数据的秘密，必须强制。 */
function assertPasswordStrength(pw) {
  const s = String(pw || '');
  if (s.length < 12) throw new VaultError('WEAK_MASTER', '主密码至少 12 位');
  if (s.length > 512) throw new VaultError('WEAK_MASTER', '主密码过长');
}

module.exports = { Vault, VaultError, CATEGORIES, strengthOf, assertPasswordStrength };