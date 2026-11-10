/**
 * جامع مسجد غوثیہ رضویہ — PWA Service Worker (sw.js)
 * Offline-First Service Worker (v2.1.0)
 * 
 * یہ سروس ورکر یقینی بناتا ہے کہ:
 * 1. ایپ انٹرنیٹ یا بجلی نہ ہونے کی صورت میں بھی فوری طور پر کیش سے کھل جائے۔
 * 2. تمام فائلز (index.html, manifest.json, tailwind.3.4.17.js) پہلی ہی بار محفوظ (Cache) ہو جائیں۔
 * 3. آف لائن ہوتے ہوئے ایپ کھولتے ہی بغیر کسی رکاوٹ کے مکمل اسکرین اور رسید فارم کھل جائے۔
 * 4. نئی اپڈیٹ آنے پر بیک گراؤنڈ میں نیا کیش لائے اور صارف کو مطلع کرے۔
 */

const CACHE_NAME = 'masjid-ghousia-shell-v2.1.0';
const APP_SHELL_ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './tailwind.3.4.17.js'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      for (const asset of APP_SHELL_ASSETS) {
        try {
          await cache.add(asset);
        } catch (err) {
          console.warn('SW pre-cache warning for asset:', asset, err);
        }
      }
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME && key.startsWith('masjid-ghousia-shell-')) {
            return caches.delete(key);
          }
          return Promise.resolve();
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = req.url;

  // Never cache Google Apps Script API or OAuth endpoints
  if (
    url.includes('script.google.com') ||
    url.includes('oauth2.googleapis.com') ||
    url.includes('accounts.google.com')
  ) {
    return;
  }

  // Handle HTML navigation (user opening the app URL, launching PWA, refreshing tab)
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const copy = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
          }
          return networkResponse;
        })
        .catch(async () => {
          // OFFLINE: Return cached page immediately!
          const cachedExact = await caches.match(req);
          if (cachedExact) return cachedExact;
          const cachedIndex = await caches.match('./index.html') || await caches.match('index.html') || await caches.match('./');
          if (cachedIndex) return cachedIndex;
          const cache = await caches.open(CACHE_NAME);
          const keys = await cache.keys();
          for (const k of keys) {
            if (k.url.endsWith('index.html') || k.url.endsWith('/')) {
              return await cache.match(k);
            }
          }
          return new Response('جامع مسجد غوثیہ رضویہ رسید ایپ — آف لائن کیش دستیاب نہیں ہے۔', {
            status: 503,
            headers: { 'Content-Type': 'text/plain; charset=utf-8' }
          });
        })
    );
    return;
  }

  // Handle assets (CSS, JS, fonts, images)
  event.respondWith(
    caches.match(req).then((cachedResponse) => {
      if (cachedResponse) {
        // Return from cache immediately, and revalidate in background if online
        fetch(req)
          .then((networkResponse) => {
            if (networkResponse && (networkResponse.status === 200 || networkResponse.type === 'opaque')) {
              const copy = networkResponse.clone();
              caches.open(CACHE_NAME).then((c) => c.put(req, copy));
            }
          })
          .catch(() => {});
        return cachedResponse;
      }

      // Not in cache yet: fetch from network and cache it
      return fetch(req)
        .then((networkResponse) => {
          if (networkResponse && (networkResponse.status === 200 || networkResponse.type === 'opaque')) {
            const copy = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, copy));
          }
          return networkResponse;
        })
        .catch(() => {
          // If Tailwind or font fails offline and not in cache, fallback
          if (url.includes('tailwind')) {
            return caches.match('./tailwind.3.4.17.js');
          }
          return new Response('', { status: 408 });
        });
    })
  );
});
