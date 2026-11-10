/* App shell only. Desk data stays in IndexedDB and is never cached here. */
const CACHE = 'seax-shell-v3';
const ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './favicon.ico',
  './assets/seax-tokens.css',
  './assets/icons/favicon.ico',
  './assets/icons/seax-small-mark-16.png',
  './assets/icons/seax-small-mark-32.png',
  './assets/icons/seax-small-mark-48.png',
  './assets/icons/seax-small-mark-64.png',
  './assets/icons/apple-touch-icon.png',
  './assets/icons/seax-badge-192.png',
  './assets/icons/seax-badge-512.png',
  './assets/icons/seax-badge-1024.png',
  './js/config.js',
  './js/time.js',
  './js/schema.js',
  './js/crypto.js',
  './js/db.js',
  './js/exif.js',
  './js/fields.js',
  './js/icons.js',
  './js/special.js',
  './js/lockout.js',
  './js/settings.js',
  './js/search.js',
  './js/media.js',
  './js/sync.js',
  './js/app.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  event.respondWith(
    fetch(event.request)
      .then((res) => {
        if (res && res.ok) {
          const copy = res.clone();
          caches.open(CACHE).then((cache) => cache.put(event.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(event.request).then((hit) => hit || caches.match('./index.html'))),
  );
});
