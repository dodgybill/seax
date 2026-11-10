/** Chunked AES-GCM for photos and videos. Thumbnails are a separate ciphertext. */

import { openBytes, sealBytes, sha256Hex } from './crypto.js';
import { exifKey, idbDel, idbGet, mediaKey, thumbKey } from './db.js';

export const CHUNK = 1024 * 1024;

export function sniffMime(bytes, fallback) {
  if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return 'image/jpeg';
  if (bytes.length >= 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return 'image/png';
  if (bytes.length >= 12 && String.fromCharCode(bytes[4], bytes[5], bytes[6], bytes[7]) === 'ftyp') {
    return fallback && fallback.startsWith('video/') ? fallback : 'video/mp4';
  }
  if (fallback && (fallback.startsWith('image/') || fallback.startsWith('video/'))) return fallback;
  return fallback || 'application/octet-stream';
}

export async function encryptMedia(dataKey, bytes) {
  const sha256 = await sha256Hex(bytes);
  const chunks = [];
  for (let o = 0; o < bytes.length; o += CHUNK) {
    const slice = bytes.subarray(o, Math.min(bytes.length, o + CHUNK));
    chunks.push(await sealBytes(dataKey, slice));
  }
  if (!chunks.length) chunks.push(await sealBytes(dataKey, new Uint8Array(0)));
  return { sha256, chunks };
}

export async function decryptMedia(dataKey, id, chunkCount) {
  const parts = [];
  let total = 0;
  for (let i = 0; i < chunkCount; i++) {
    const box = await idbGet(mediaKey(id, i));
    if (!box) throw new Error('A media chunk is missing.');
    const part = await openBytes(dataKey, box);
    parts.push(part);
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function deleteMediaBlobs(id, chunkCount = 0) {
  const n = Math.max(chunkCount, 0);
  for (let i = 0; i < n; i++) await idbDel(mediaKey(id, i));
  await idbDel(exifKey(id));
  await idbDel(thumbKey(id));
}

/** In-memory preview only. Returns null for video or if the browser cannot decode the image. */
export async function makeThumbBytes(file) {
  if (!file || !file.type || !file.type.startsWith('image/')) return null;
  try {
    const bmp = await createImageBitmap(file);
    const max = 160;
    const scale = Math.min(1, max / Math.max(bmp.width, bmp.height));
    const w = Math.max(1, Math.round(bmp.width * scale));
    const h = Math.max(1, Math.round(bmp.height * scale));
    const canvas = document.createElement('canvas');
    canvas.width = w;
    canvas.height = h;
    canvas.getContext('2d').drawImage(bmp, 0, 0, w, h);
    if (bmp.close) bmp.close();
    const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', 0.72));
    if (!blob) return null;
    return new Uint8Array(await blob.arrayBuffer());
  } catch {
    return null;
  }
}
