/**
 * SyncAdapter
 * -----------
 * Plug-in point for moving an encrypted desk between devices.
 *
 * v1 ships BundleSyncAdapter only: a file the operator carries
 * (AirDrop, a cable, a disk). The file is AES-256-GCM under a key
 * derived from the passphrase (PBKDF2-SHA256, 600,000 iterations)
 * and carries a SHA-256 of the ciphertext plus the GCM tag.
 *
 * A later CloudSyncAdapter can put that same opaque bundle in a
 * store that never receives the passphrase, the data key, or the
 * recovery key. The server would hold ciphertext only.
 * Merge stays here: last-writer-wins per record on updatedAt,
 * with the losing version kept on the desk and named in the audit log.
 *
 *   class CloudSyncAdapter extends SyncAdapter {
 *     constructor(ciphertextStore) { super(); this.store = ciphertextStore; }
 *     async push(bundleBytes) { await this.store.put(bundleBytes); }
 *     async pull() { return this.store.get(); }
 *   }
 */

import {
  ITERATIONS,
  deriveKek,
  fromB64,
  importDataKey,
  openBytes,
  openJson,
  sealBytes,
  sealJson,
  sha256Hex,
  toB64,
  verifyChain,
  wrapDataKey,
} from './crypto.js';
import { exifKey, mediaKey, thumbKey } from './db.js';
import { assertClean, normalise } from './schema.js';

const MAGIC = 'SEAXBND1';

export class SyncAdapter {
  async exportBundle() {
    throw new Error('SyncAdapter.exportBundle is not implemented');
  }
  async importBundle() {
    throw new Error('SyncAdapter.importBundle is not implemented');
  }
}

/** Seam only. v1 does not connect a server. */
export class CloudSyncAdapter extends SyncAdapter {
  constructor(ciphertextStore) {
    super();
    this.ciphertextStore = ciphertextStore;
  }
  async exportBundle() {
    throw new Error('Cloud sync is not connected in v1. A store would receive ciphertext only.');
  }
  async importBundle() {
    throw new Error('Cloud sync is not connected in v1. A store would receive ciphertext only.');
  }
}

export class BundleSyncAdapter extends SyncAdapter {
  constructor(api) {
    super();
    this.api = api;
  }

  async exportBundle(passphrase, kind) {
    if (kind !== 'sync' && kind !== 'backup') throw new Error('Unknown bundle kind.');
    await this.api.assertPassphrase(passphrase);
    const payload = await this.gather(kind);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const kek = await deriveKek(passphrase, salt);
    const pt = new TextEncoder().encode(JSON.stringify(payload));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, pt));
    const sha256 = await sha256Hex(ct);
    const header = { v: 1, kind, iterations: ITERATIONS, salt: toB64(salt), iv: toB64(iv), sha256 };
    return packBundle(header, ct);
  }

  async verifyBundle(bytes, passphrase) {
    const { payload } = await openBundle(bytes, passphrase);
    return { ok: true, kind: payload.kind, exportedAt: payload.exportedAt, ...counts(payload.state) };
  }

  async importBundle(bytes, passphrase, mode) {
    const { payload } = await openBundle(bytes, passphrase);
    if (mode === 'merge' && payload.kind !== 'sync') throw new Error('This file is a backup, not a sync bundle.');
    if (mode === 'replace' && payload.kind !== 'backup') throw new Error('This file is a sync bundle, not a backup.');
    const has = await this.api.hasVault();
    if (mode === 'replace' || !has) {
      const action = mode === 'replace' || payload.kind === 'backup' ? 'RESTORE' : 'SYNC_IMPORT';
      await this.adopt(payload, passphrase, action);
      return { mode: 'adopt', conflicts: [], counts: counts(this.api.getState()) };
    }
    if (!this.api.getDataKey()) throw new Error('Sign in before merging into this device.');
    const conflicts = await this.merge(payload);
    return { mode: 'merge', conflicts, counts: counts(this.api.getState()) };
  }

  async gather(kind) {
    const dataKey = this.api.getDataKey();
    const state = this.api.getState();
    const vault = await this.api.getVault();
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', dataKey));
    const media = {};
    for (const item of state.media || []) {
      const chunks = [];
      for (let i = 0; i < item.chunks; i++) {
        const box = await this.api.getRecord(mediaKey(item.id, i));
        if (!box) throw new Error('Media is incomplete on this device.');
        chunks.push(toB64(await openBytes(dataKey, box)));
      }
      let thumb = null;
      const t = await this.api.getRecord(thumbKey(item.id));
      if (t) thumb = toB64(await openBytes(dataKey, t));
      media[item.id] = { chunks, thumb };
    }
    const exif = {};
    for (const item of state.media || []) {
      const box = await this.api.getRecord(exifKey(item.id));
      if (box) exif[item.id] = await openJson(dataKey, box);
    }
    const payload = {
      v: 1,
      kind,
      exportedAt: new Date().toISOString(),
      dataKey: toB64(raw),
      recoveryWrap: { iv: toB64(vault.recoveryWrap.iv), ct: toB64(vault.recoveryWrap.ct) },
      state,
      media,
      exif,
    };
    raw.fill(0);
    return payload;
  }

  async adopt(payload, passphrase, action) {
    const raw = fromB64(payload.dataKey);
    const dataKey = await importDataKey(raw);
    raw.fill(0);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const kek = await deriveKek(passphrase, salt);
    const passWrap = await wrapDataKey(dataKey, kek);
    const recoveryWrap = { iv: fromB64(payload.recoveryWrap.iv), ct: fromB64(payload.recoveryWrap.ct) };
    await this.api.putVault({
      v: 1,
      iterations: ITERATIONS,
      salt,
      passWrap,
      recoveryWrap,
      createdAt: new Date().toISOString(),
    });
    await this.api.wipeRecords();
    this.api.setDataKey(dataKey);
    const state = normalise(structuredClone(payload.state));
    this.api.setState(state);
    for (const item of state.media || []) {
      if (payload.media && payload.media[item.id]) {
        await this.storeMedia(item.id, payload.media[item.id], payload.exif && payload.exif[item.id], dataKey);
      }
    }
    await this.api.audit(action, payload.exportedAt);
    await this.api.saveState();
  }

  async merge(payload) {
    const localBefore = structuredClone(this.api.getState());
    const remote = normalise(structuredClone(payload.state));
    const { state: merged, conflicts } = mergeStates(localBefore, remote);
    this.api.setState(merged);
    await this.writeWinningMedia(payload, localBefore, remote);
    await this.api.audit('SYNC_MERGE', `imported ${payload.exportedAt}; conflicts ${conflicts.length}`);
    for (const c of conflicts) {
      await this.api.audit('SYNC_CONFLICT', `${c.collection} ${c.id} kept ${c.kept}`);
    }
    await this.api.saveState();
    return conflicts;
  }

  async writeWinningMedia(payload, localBefore, remote) {
    const dataKey = this.api.getDataKey();
    const state = this.api.getState();
    const localMap = new Map((localBefore.media || []).map((m) => [m.id, m]));
    for (const item of state.media || []) {
      const loc = localMap.get(item.id);
      const rem = (remote.media || []).find((m) => m.id === item.id);
      const useRemote = rem && (!loc || Date.parse(rem.updatedAt || 0) >= Date.parse(loc.updatedAt || 0));
      if (useRemote && payload.media && payload.media[item.id]) {
        await this.storeMedia(item.id, payload.media[item.id], payload.exif && payload.exif[item.id], dataKey);
      }
    }
  }

  async storeMedia(id, packed, exif, dataKey) {
    await this.api.deleteMediaBlobs(id);
    const chunks = packed.chunks || [];
    for (let i = 0; i < chunks.length; i++) {
      await this.api.putRecord(mediaKey(id, i), await sealBytes(dataKey, fromB64(chunks[i])));
    }
    if (packed.thumb) await this.api.putRecord(thumbKey(id), await sealBytes(dataKey, fromB64(packed.thumb)));
    if (exif) await this.api.putRecord(exifKey(id), await sealJson(dataKey, exif));
  }
}

export function packBundle(header, ct) {
  const h = new TextEncoder().encode(JSON.stringify(header));
  const out = new Uint8Array(8 + 4 + h.length + ct.length);
  out.set(new TextEncoder().encode(MAGIC), 0);
  new DataView(out.buffer).setUint32(8, h.length, true);
  out.set(h, 12);
  out.set(ct, 12 + h.length);
  return out;
}

export function unpackBundle(bytes) {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (u.length < 16) throw new Error('This file is not a SEAX bundle.');
  const magic = new TextDecoder().decode(u.subarray(0, 8));
  if (magic !== MAGIC) throw new Error('This file is not a SEAX bundle.');
  const len = new DataView(u.buffer, u.byteOffset, u.byteLength).getUint32(8, true);
  if (len < 2 || 12 + len > u.length) throw new Error('This file is not a SEAX bundle.');
  let header;
  try {
    header = JSON.parse(new TextDecoder().decode(u.subarray(12, 12 + len)));
  } catch {
    throw new Error('This file is not a SEAX bundle.');
  }
  const ct = new Uint8Array(u.subarray(12 + len));
  return { header, ct };
}

async function openBundle(bytes, passphrase) {
  const { header, ct } = unpackBundle(bytes);
  if (!header || header.v !== 1) throw new Error('This bundle version is not supported.');
  if ((header.iterations || 0) < ITERATIONS) throw new Error('This bundle uses a key derivation that is too weak.');
  const sum = await sha256Hex(ct);
  if (sum !== header.sha256) throw new Error('This file failed the integrity check.');
  if (!passphrase) throw new Error('Passphrase is required.');
  const kek = await deriveKek(passphrase, fromB64(header.salt), header.iterations);
  let pt;
  try {
    pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(header.iv) }, kek, ct);
  } catch {
    throw new Error('Could not open this file. Check the passphrase.');
  }
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(pt));
  } catch {
    throw new Error('This file failed the integrity check.');
  }
  if (!payload || payload.kind !== header.kind || !payload.state) {
    throw new Error('This file failed the integrity check.');
  }
  assertClean(payload.state);
  if (!payload.state.owner || !payload.state.owner.name) throw new Error('This file failed the integrity check.');
  if (!(await verifyChain(payload.state.audit))) throw new Error('The audit chain in this file does not verify.');
  for (const item of payload.state.media || []) {
    if (!item.id || !item.sha256) throw new Error('This file failed the integrity check.');
  }
  return { header, payload };
}

function counts(state) {
  return {
    cases: (state.cases || []).length,
    entries: (state.ents || []).length,
    media: (state.media || []).length,
    audit: (state.audit || []).length,
  };
}

function stable(v) {
  if (Array.isArray(v)) return v.map(stable);
  if (v && typeof v === 'object') {
    return Object.keys(v)
      .sort()
      .reduce((o, k) => {
        o[k] = stable(v[k]);
        return o;
      }, {});
  }
  return v;
}

function same(a, b) {
  return JSON.stringify(stable(a)) === JSON.stringify(stable(b));
}

export function mergeStates(local, remote) {
  const conflicts = [];
  const next = structuredClone(local);
  next.cases = lww(local.cases, remote.cases, conflicts, 'cases');
  next.ents = lww(local.ents, remote.ents, conflicts, 'ents');
  next.tasks = lww(local.tasks, remote.tasks, conflicts, 'tasks');
  next.media = lww(local.media, remote.media, conflicts, 'media');
  next.links = lww(local.links, remote.links, conflicts, 'links');
  next.tombstones = lww(local.tombstones, remote.tombstones, conflicts, 'tombstones');
  next.fieldDefs = lww(local.fieldDefs, remote.fieldDefs, conflicts, 'fieldDefs');
  const lt = Date.parse((local.attest && local.attest.updatedAt) || 0);
  const rt = Date.parse((remote.attest && remote.attest.updatedAt) || 0);
  if (remote.attest && rt >= lt && !same(local.attest || {}, remote.attest)) {
    if (local.attest && local.attest.updatedAt) {
      conflicts.push({
        collection: 'attest',
        id: 'attest',
        at: new Date().toISOString(),
        kept: 'imported',
        discarded: local.attest,
      });
    }
    next.attest = structuredClone(remote.attest);
  }
  applyTombstones(next);
  next.conflicts = [...(local.conflicts || []), ...conflicts];
  next.retainedAudits = [...(local.retainedAudits || [])];
  const localHead = local.audit && local.audit.length ? local.audit[local.audit.length - 1].hash : '';
  const remoteHead = remote.audit && remote.audit.length ? remote.audit[remote.audit.length - 1].hash : '';
  const already = (local.retainedAudits || []).some((a) => a.head === remoteHead);
  if (remoteHead && remoteHead !== localHead && !already) {
    next.retainedAudits.push({ head: remoteHead, at: new Date().toISOString(), audit: remote.audit });
  }
  if (!(next.cases || []).find((c) => c.id === next.curCase)) next.curCase = (next.cases[0] && next.cases[0].id) || null;
  next.owner = local.owner || next.owner;
  return { state: next, conflicts };
}

function lww(localList, remoteList, conflicts, collection) {
  const map = new Map();
  for (const rec of localList || []) if (rec && rec.id) map.set(rec.id, rec);
  for (const rec of remoteList || []) {
    if (!rec || !rec.id) continue;
    const cur = map.get(rec.id);
    if (!cur) {
      map.set(rec.id, rec);
      continue;
    }
    if (same(cur, rec)) continue;
    const ct = Date.parse(cur.updatedAt || 0);
    const rt = Date.parse(rec.updatedAt || 0);
    if (rt >= ct) {
      conflicts.push({ collection, id: rec.id, at: new Date().toISOString(), kept: 'imported', discarded: cur });
      map.set(rec.id, rec);
    } else {
      conflicts.push({ collection, id: rec.id, at: new Date().toISOString(), kept: 'local', discarded: rec });
    }
  }
  return [...map.values()];
}

function applyTombstones(state) {
  const tombs = new Map((state.tombstones || []).map((t) => [`${t.collection}:${t.target}`, t]));
  for (const coll of ['cases', 'ents', 'tasks', 'media', 'links', 'fieldDefs']) {
    state[coll] = (state[coll] || []).filter((rec) => {
      const tomb = tombs.get(`${coll}:${rec.id}`);
      if (!tomb) return true;
      return Date.parse(rec.updatedAt || 0) > Date.parse(tomb.updatedAt || 0);
    });
  }
}
