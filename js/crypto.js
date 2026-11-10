/** AES-256-GCM, PBKDF2-SHA256, and the audit hash. WebCrypto only. */

export const ITERATIONS = 600_000;
export const IDLE_MS = 15 * 60 * 1000;
export const LOCKOUT_MS = 15 * 60 * 1000;
export const LOCKOUT_MAX = 5;

const text = new TextEncoder();
const textOut = new TextDecoder();

export function asBytes(b) {
  if (b instanceof Uint8Array) return new Uint8Array(b);
  if (b instanceof ArrayBuffer) return new Uint8Array(b);
  if (ArrayBuffer.isView(b)) return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  if (b && typeof b === 'object') {
    const keys = Object.keys(b);
    if (keys.length && keys.every((k) => /^\d+$/.test(k))) {
      const out = new Uint8Array(keys.length);
      for (const k of keys) out[Number(k)] = b[k];
      return out;
    }
  }
  throw new Error('Expected bytes');
}

export function toB64(bytes) {
  const u = asBytes(bytes);
  let s = '';
  const step = 0x8000;
  for (let i = 0; i < u.length; i += step) {
    s += String.fromCharCode(...u.subarray(i, i + step));
  }
  return btoa(s);
}

export function fromB64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export async function sha256Hex(data) {
  const buf = typeof data === 'string' ? text.encode(data) : asBytes(data);
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function deriveKek(passphrase, salt, iterations = ITERATIONS) {
  if (!Number.isInteger(iterations) || iterations < ITERATIONS) {
    throw new Error('Key derivation is below the minimum.');
  }
  const base = await crypto.subtle.importKey('raw', text.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: asBytes(salt), iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
  );
}

export async function generateDataKey() {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function importDataKey(raw) {
  const bytes = asBytes(raw);
  if (bytes.length !== 32) throw new Error('Data key is the wrong length.');
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function importRawKey(raw) {
  const bytes = asBytes(raw);
  if (bytes.length !== 32) throw new Error('Recovery key is the wrong length.');
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM', length: 256 }, false, ['wrapKey', 'unwrapKey']);
}

export async function wrapDataKey(dataKey, kek) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.wrapKey('raw', dataKey, kek, { name: 'AES-GCM', iv }));
  return { iv, ct };
}

export async function unwrapDataKey(box, kek) {
  const iv = asBytes(box.iv);
  const ct = asBytes(box.ct);
  return crypto.subtle.unwrapKey(
    'raw',
    ct,
    kek,
    { name: 'AES-GCM', iv },
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

export function normaliseBox(box) {
  if (!box || box.iv == null || box.ct == null) throw new Error('Encrypted record is incomplete.');
  return { iv: asBytes(box.iv), ct: asBytes(box.ct) };
}

export async function sealBytes(key, bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, asBytes(bytes)));
  return { iv, ct };
}

export async function openBytes(key, box) {
  const { iv, ct } = normaliseBox(box);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new Uint8Array(pt);
}

export async function sealJson(key, value) {
  return sealBytes(key, text.encode(JSON.stringify(value)));
}

export async function openJson(key, box) {
  const pt = await openBytes(key, box);
  return JSON.parse(textOut.decode(pt));
}

/** Same concatenation as the launch desk: prev + time + who + action + detail. */
export async function auditHash(entry) {
  return sha256Hex(entry.prev + entry.t + entry.who + entry.action + entry.detail);
}

export async function verifyChain(audit) {
  let prev = 'GENESIS';
  for (const entry of audit || []) {
    if (entry.prev !== prev) return false;
    if ((await auditHash(entry)) !== entry.hash) return false;
    prev = entry.hash;
  }
  return true;
}

const ALPH = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function normaliseKeyText(textValue) {
  return String(textValue || '')
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, '')
    .replace(/I/g, '1')
    .replace(/L/g, '1')
    .replace(/O/g, '0')
    .replace(/U/g, 'V');
}

/** 32 bytes -> 13 groups of 4 Crockford base32 characters. */
export function encodeKey(bytes) {
  const u = asBytes(bytes);
  if (u.length !== 32) throw new Error('Recovery key must be 32 bytes.');
  let bits = 0;
  let val = 0;
  let out = '';
  for (const b of u) {
    val = (val << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPH[(val >> bits) & 31];
    }
  }
  if (bits > 0) out += ALPH[(val << (5 - bits)) & 31];
  const groups = [];
  for (let i = 0; i < out.length; i += 4) groups.push(out.slice(i, i + 4));
  if (groups.length !== 13 || groups.some((g) => g.length !== 4)) {
    throw new Error('Recovery key could not be grouped.');
  }
  return groups;
}

export function decodeKey(textValue) {
  const clean = normaliseKeyText(textValue);
  if (clean.length < 52) throw new Error('Enter the full recovery key.');
  let bits = 0;
  let val = 0;
  const out = [];
  for (let i = 0; i < 52; i++) {
    const idx = ALPH.indexOf(clean[i]);
    if (idx < 0) throw new Error('Recovery key has a character that is not valid.');
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((val >> bits) & 255);
    }
  }
  if (out.length < 32) throw new Error('Recovery key is incomplete.');
  return new Uint8Array(out.slice(0, 32));
}
