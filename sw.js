// ══════════════════════════════════════════
// SG ChatBOT — Service Worker v2.0
// Features: Offline cache + Push notifications
// ══════════════════════════════════════════

const CACHE_VERSION = 'sg-chatbot-v2';
const STATIC_CACHE  = 'sg-static-v2';
const API_ORIGIN    = 'sg-chatbot-z8hp.onrender.com';

const STATIC_ASSETS = [
  '/chat.html',
  '/index.html',
  '/pricing.html',
  '/settings.html',
  '/logo.svg',
  '/manifest.json',
];

// ── Install ──
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => cache.addAll(STATIC_ASSETS).catch(() => {}))
      .then(() => self.skipWaiting())
  );
});

// ── Activate: clean old caches ──
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(k => k !== CACHE_VERSION && k !== STATIC_CACHE)
          .map(k => caches.delete(k))
      )
    ).then(() => self.clients.claim())
  );
});

// ── Fetch: skip API, cache static ──
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  if (event.request.method !== 'GET') return;

  // Never intercept API or CDN calls
  if (
    url.hostname.includes(API_ORIGIN) ||
    url.hostname.includes('onrender.com') ||
    url.hostname.includes('openrouter') ||
    url.hostname.includes('groq') ||
    url.hostname.includes('googleapis') ||
    url.hostname.includes('jsdelivr') ||
    url.hostname.includes('gstatic') ||
    url.hostname.includes('fonts.g')
  ) return;

  event.respondWith(
    caches.match(event.request).then(cached => {
      if (cached) return cached;
      return fetch(event.request).then(response => {
        if (response && response.status === 200 && response.type === 'basic') {
          const clone = response.clone();
          caches.open(STATIC_CACHE).then(cache => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => {
        if (event.request.mode === 'navigate') {
          return caches.match('/chat.html');
        }
      });
    })
  );
});

// ── Push Notification ──
self.addEventListener('push', event => {
  let data = { title: 'SG ChatBOT', body: 'You have a new message!', icon: '/logo.svg' };
  try { data = { ...data, ...event.data.json() }; } catch {}

  event.waitUntil(
    self.registration.showNotification(data.title, {
      body:    data.body,
      icon:    data.icon || '/logo.svg',
      badge:   '/logo.svg',
      vibrate: [200, 100, 200],
      tag:     'sg-chatbot-notification',
      data:    { url: data.url || '/chat.html' },
      actions: [
        { action: 'open',    title: '💬 Open Chat' },
        { action: 'dismiss', title: '✕ Dismiss'    },
      ],
    })
  );
});

// ── Notification Click ──
self.addEventListener('notificationclick', event => {
  event.notification.close();
  if (event.action === 'dismiss') return;

  const url = event.notification.data?.url || '/chat.html';
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      const existing = list.find(c => c.url.includes('chat.html'));
      if (existing) return existing.focus();
      return clients.openWindow(url);
    })
  );
});

// ── Message from page ──
self.addEventListener('message', event => {
  if (event.data === 'skipWaiting') self.skipWaiting();
});
