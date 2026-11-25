'use strict';
/**
 * Qsecret 加密内核
 *
 * 设计要点（任何改动都必须先读这里）：
 *  1. 主密码永不落盘，只用于 scrypt 派生密钥。
 *  2. scrypt 参数（N/r/p）随文件保存，便于未来提高成本而不破坏旧文件。
 *  3. 派生出的主密钥经 HKDF-SHA256 分成三把互不通用的子密钥：
 *       encKey  —— AES-256-GCM 加密条目
 *       macKey  —— HMAC-SHA256 对整个文件做“封印”，防删条目/换顺序/改头部
 *       verKey  —— 加密固定哨兵，用于校验主密码是否正确（不用存哈希）
 *  4. 每条目独立 IV（96-bit 随机），AAD 绑定 vaultId + 条目 id + 版本号。
 *     这样攻击者无法把 A 条目的密文挪到 B 条目下，也无法回滚到旧版本。
 *  5. 所有比较使用 timingSafeEqual。
 */

const crypto = require('node:crypto');

const FORMAT = 'qsecret-vault';
const VERSION = 1;

const KEY_LEN = 32;
const IV_LEN = 12;
const TAG_LEN = 16;
const SALT_LEN = 16;

// 约 128 MiB 内存 / 单次解锁 ~0.3–1s（依机器而定）。
// 攻击者若拿到文件，每次猜测都要付出同样的内存与时间成本，GPU/ASIC 难以并行。
const KDF_DEFAULT = Object.freeze({ algo: 'scrypt', N: 1 << 17, r: 8, p: 1 });
const KDF_MAXMEM = 1024 * 1024 * 1024;

const VERIFIER_PLAINTEXT = 'qsecret:verifier:v1';

class CryptoError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const b64 = (buf) => Buffer.from(buf).toString('base64');
const unb64 = (str) => Buffer.from(String(str), 'base64');

/** 统一密码编码，避免不同输入法/平台产生不同字节序列。 */
function normalizePassword(pw) {
  return String(pw).normalize('NFKC');
}

function randomBytes(n) {
  return crypto.randomBytes(n);
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function uuid() {
  return crypto.randomUUID();
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data).digest();
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/** scrypt 派生 + HKDF 分离子密钥。返回的 Buffer 由调用方负责 fill(0)。 */
function deriveKeys(password, salt, kdf) {
  const params = kdf || KDF_DEFAULT;
  if (params.algo !== 'scrypt') throw new CryptoError('UNSUPPORTED_KDF');
  if (!Number.isInteger(params.N) || params.N < 1 << 14 || (params.N & (params.N - 1)) !== 0) {
    throw new CryptoError('BAD_KDF_PARAMS');
  }

  let master;
  try {
    master = crypto.scryptSync(normalizePassword(password), salt, KEY_LEN, {
      N: params.N,
      r: params.r,
      p: params.p,
      maxmem: KDF_MAXMEM,
    });
  } catch (err) {
    // 参数异常或内存不足，绝不回退到更弱的参数
    throw new CryptoError('KDF_FAILED');
  }

  const expand = (info) =>
    Buffer.from(crypto.hkdfSync('sha256', master, salt, `qsecret:v1:${info}`, KEY_LEN));

  const keys = {
    encKey: expand('enc'),
    macKey: expand('mac'),
    verKey: expand('verify'),
    wipe() {
      master.fill(0);
      this.encKey.fill(0);
      this.macKey.fill(0);
      this.verKey.fill(0);
    },
  };
  master.fill(0);
  return keys;
}

/** AES-256-GCM 加密，返回 {n, ct, tag} 三段 base64。 */
function seal(key, plaintext, aad) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const pt = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext, 'utf8');
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { n: b64(iv), ct: b64(ct), tag: b64(tag) };
}

/** 解密并校验 AAD；任何异常统一抛 AUTH_FAILED，不泄露细节。 */
function open(key, box, aad) {
  if (!box || typeof box.n !== 'string' || typeof box.ct !== 'string' || typeof box.tag !== 'string') {
    throw new CryptoError('BLOB_MALFORMED');
  }
  const iv = unb64(box.n);
  const ct = unb64(box.ct);
  const tag = unb64(box.tag);
  if (iv.length !== IV_LEN || tag.length !== TAG_LEN) throw new CryptoError('BLOB_MALFORMED');

  let decipher;
  try {
    decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LEN });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new CryptoError('AUTH_FAILED');
  }
}

function aadVerifier(vaultId) {
  return `${FORMAT}|v|${VERSION}|verifier|${vaultId}`;
}

function aadEntry(vaultId, id, rev) {
  return `${FORMAT}|v|${VERSION}|entry|${vaultId}|${id}|${rev}`;
}

function aadMeta(vaultId) {
  return `${FORMAT}|v|${VERSION}|meta|${vaultId}`;
}

/** 规范化的封印输入：任何字段变动都会改变 MAC。 */
function macInput(data) {
  const lines = [
    FORMAT,
    String(VERSION),
    data.vaultId,
    JSON.stringify(data.kdf),
    JSON.stringify(data.verifier),
    String(data.revision),
  ];
  for (const e of data.entries) {
    lines.push(`${e.id}|${e.rev}|${e.n}|${e.ct}|${e.tag}`);
  }
  lines.push(data.meta ? `${data.meta.n}|${data.meta.ct}|${data.meta.tag}` : '-');
  return lines.join('\n');
}

function fileMac(macKey, data) {
  return b64(hmac(macKey, macInput(data)));
}

function newSalt() {
  return crypto.randomBytes(SALT_LEN);
}

/** 生成新保险库骨架（尚不含条目）。 */
function createHeader(password, kdf = KDF_DEFAULT) {
  const salt = newSalt();
  const vaultId = b64(randomBytes(16));
  const keys = deriveKeys(password, salt, kdf);

  const header = {
    format: FORMAT,
    version: VERSION,
    vaultId,
    kdf: { algo: kdf.algo, N: kdf.N, r: kdf.r, p: kdf.p, salt: b64(salt) },
    verifier: null,
    revision: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    entries: [],
    meta: null,
    mac: null,
  };

  header.verifier = seal(
    keys.verKey,
    Buffer.from(VERIFIER_PLAINTEXT, 'utf8'),
    aadVerifier(vaultId)
  );
  header.meta = seal(
    keys.encKey,
    JSON.stringify({ settings: { idleMinutes: 5 } }),
    aadMeta(vaultId)
  );
  header.mac = fileMac(keys.macKey, header);
  return { header, keys, salt };
}

/**
 * 校验主密码：解密哨兵并用常量时间比较。
 * 返回子密钥；密码错误抛 BAD_PASSWORD。
 */
function unlockHeader(header, password) {
  const salt = unb64(header.kdf.salt);
  let keys;
  try {
    keys = deriveKeys(password, salt, header.kdf);
  } catch {
    throw new CryptoError('BAD_PASSWORD');
  }

  let plain;
  try {
    plain = open(keys.verKey, header.verifier, aadVerifier(header.vaultId));
  } catch (err) {
    keys.wipe();
    throw new CryptoError('BAD_PASSWORD');
  }

  const ok = safeEqual(plain.toString('utf8'), VERIFIER_PLAINTEXT);
  plain.fill(0);
  if (!ok) {
    keys.wipe();
    throw new CryptoError('BAD_PASSWORD');
  }

  // 文件级封印：能解开哨兵但 MAC 不对 => 文件被改过，拒绝打开
  const expect = fileMac(keys.macKey, header);
  if (!safeEqual(expect, header.mac || '')) {
    keys.wipe();
    throw new CryptoError('TAMPERED');
  }

  return { keys, salt };
}

/** 无密码检查文件是否像 Qsecret 保险库（用于给出更准确的错误提示）。 */
function looksLikeVault(raw) {
  try {
    const data = JSON.parse(raw);
    return data && data.format === FORMAT && typeof data.vaultId === 'string';
  } catch {
    return false;
  }
}

function validateKdf(kdf) {
  return (
    kdf &&
    kdf.algo === 'scrypt' &&
    Number.isInteger(kdf.N) &&
    kdf.N >= 1 << 14 &&
    kdf.N <= 1 << 20 &&
    (kdf.N & (kdf.N - 1)) === 0 &&
    Number.isInteger(kdf.r) &&
    kdf.r >= 1 &&
    kdf.r <= 32 &&
    Number.isInteger(kdf.p) &&
    kdf.p >= 1 &&
    kdf.p <= 8
  );
}

module.exports = {
  FORMAT,
  VERSION,
  KDF_DEFAULT,
  CryptoError,
  b64,
  unb64,
  normalizePassword,
  randomBytes,
  randomToken,
  uuid,
  hmac,
  safeEqual,
  deriveKeys,
  seal,
  open,
  aadVerifier,
  aadEntry,
  aadMeta,
  macInput,
  fileMac,
  newSalt,
  createHeader,
  unlockHeader,
  looksLikeVault,
  validateKdf,
};