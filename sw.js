// ══════════════════════════════════════════
// SG ChatBOT — Service Worker
// Version: 1.0.0
// ══════════════════════════════════════════

const CACHE_NAME   = 'sg-chatbot-v1';
const STATIC_CACHE = 'sg-static-v1';
const API_ORIGIN   = 'sg-chatbot-z8hp.onrender.com';

// Files to cache on install
const STATIC_ASSETS = [
  '/',
  '/chat.html',
  '/index.html',
  '/pricing.html',
  '/settings.html',
  '/logo.svg',
  '/manifest.json',
];

// ── Install: pre-cache static assets ──
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => cache.addAll(STATIC_ASSETS).catch(() => {}))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: clean up old caches ──
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_NAME && k !== STATIC_CACHE)
          .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: network-first for API, cache-first for static ──
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  // Skip API calls — always go to network
  if (
    url.hostname === API_ORIGIN ||
    url.hostname.includes('openrouter') ||
    url.hostname.includes('groq') ||
    url.hostname.includes('googleapis') ||
    url.hostname.includes('jsdelivr') ||
    url.hostname.includes('fonts.g')
  ) return;

  // Static assets: cache-first with network fallback
  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        // Cache successful responses
        if (response && response.status === 200 && response.type === 'basic') {
          const clone = response.clone();
          caches.open(STATIC_CACHE).then(cache => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => {
        // Offline fallback for navigation requests
        if (event.request.mode === 'navigate') {
          return caches.match('/chat.html');
        }
      });
    })
  );
});

// ── Background sync message ──
self.addEventListener('message', event => {
  if (event.data === 'skipWaiting') self.skipWaiting();
});
