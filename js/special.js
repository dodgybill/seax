/**
 * Special-category values use a second AES-GCM key derived from the desk data key.
 * The record blob is still encrypted at rest. Search, lists and bulk export never
 * receive the plaintext.
 */

import { fromB64, openBytes, sealBytes, toB64 } from './crypto.js';

const text = new TextEncoder();
const textOut = new TextDecoder();

export async function deriveFieldKey(dataKey) {
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', dataKey));
  const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  raw.fill(0);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: text.encode('seax-special-category-v1'),
      info: text.encode('special-category'),
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export function isSealedSpecial(value) {
  return !!(value && typeof value === 'object' && value.seaxSpecial === 1 && value.iv && value.ct);
}

export async function sealSpecialValue(fieldKey, value) {
  const box = await sealBytes(fieldKey, text.encode(JSON.stringify(value)));
  return { seaxSpecial: 1, iv: toB64(box.iv), ct: toB64(box.ct) };
}

export async function openSpecialValue(fieldKey, sealed) {
  if (!isSealedSpecial(sealed)) return null;
  const pt = await openBytes(fieldKey, { iv: fromB64(sealed.iv), ct: fromB64(sealed.ct) });
  return JSON.parse(textOut.decode(pt));
}
