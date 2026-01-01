

const CACHE_NAME = 'nulla-v1';
const urlsToCache = [
  '/',
  '/html/index.html',
  '/css/main.css',
  '/js/storage.js',
  '/js/crypto.js',
  '/js/api.js',
  '/js/ws.js',
  '/js/app.js',
  '/manifest/manifest.json'
];


self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        return cache.addAll(urlsToCache);
      })
      .catch((error) => {
      })
  );
  self.skipWaiting();
});


self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  return self.clients.claim();
});


self.addEventListener('fetch', (event) => {

  if (event.request.url.includes('/ws') || event.request.url.includes('/api/')) {
    return;
  }
  
  event.respondWith(
    caches.match(event.request)
      .then((response) => {

        return response || fetch(event.request);
      })
      .catch(() => {

        if (event.request.destination === 'document') {
          return caches.match('/html/index.html');
        }
      })
  );
});

