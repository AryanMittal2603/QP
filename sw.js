// Offline cache for the Randomization Console page. API calls always go to the network.
const CACHE = 'upessc-qpr-v1';
const SHELL = ['/', '/index.html'];
self.addEventListener('install', e => { e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin || url.pathname.startsWith('/api')) return;
  if (e.request.mode === 'navigate' || SHELL.includes(url.pathname)) {
    // network first (to pick up new releases), fall back to cache when offline
    e.respondWith(fetch(e.request).then(r => { const copy = r.clone(); caches.open(CACHE).then(c => c.put('/index.html', copy)); return r; })
      .catch(() => caches.match('/index.html')));
  }
});
