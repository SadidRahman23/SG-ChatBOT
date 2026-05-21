// SW disabled — unregister immediately
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', () => {
  self.clients.matchAll().then(clients => clients.forEach(c => c.navigate(c.url)));
  return self.clients.claim();
});
