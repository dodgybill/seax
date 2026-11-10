/** IndexedDB. Values are ciphertext except the vault wraps and the lockout counter. */

export const DB_NAME = 'seax-intelligence';
export const VAULT_KEY = 'vault';
export const LOCKOUT_KEY = 'lockout';
export const STATE_KEY = 's';

export function mediaKey(id, i) {
  return `b:${id}:${i}`;
}
export function exifKey(id) {
  return `x:${id}`;
}
export function thumbKey(id) {
  return `t:${id}`;
}

let dbPromise = null;

function requestToPromise(req) {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export function openDb() {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        const db = req.result;
        if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv');
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  return dbPromise;
}

export async function idbGet(key) {
  const db = await openDb();
  return requestToPromise(db.transaction('kv', 'readonly').objectStore('kv').get(key));
}

export async function idbSet(key, value) {
  const db = await openDb();
  const tx = db.transaction('kv', 'readwrite');
  tx.objectStore('kv').put(value, key);
  await txDone(tx);
}

export async function idbDel(key) {
  const db = await openDb();
  const tx = db.transaction('kv', 'readwrite');
  tx.objectStore('kv').delete(key);
  await txDone(tx);
}

export async function idbAll() {
  const db = await openDb();
  const tx = db.transaction('kv', 'readonly');
  const store = tx.objectStore('kv');
  const keys = await requestToPromise(store.getAllKeys());
  const vals = await requestToPromise(store.getAll());
  await txDone(tx);
  return keys.map((k, i) => [k, vals[i]]);
}

function txDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
  });
}

export async function idbDeleteDb() {
  if (dbPromise) {
    try {
      const db = await dbPromise;
      db.close();
    } catch {
      /* already closed */
    }
  }
  dbPromise = null;
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
    req.onblocked = () => resolve();
  });
}
