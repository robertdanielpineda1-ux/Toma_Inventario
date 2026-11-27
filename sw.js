// Service worker: deja la app funcionando sin internet
const CACHE = "inventario-v29";
const SHELL = ["./", "./index.html", "./config.js", "./manifest.json", "./icon-192.png", "./icon-512.png",
  "./lib/xlsx.bundle.js", "./lib/jspdf.umd.min.js", "./lib/jspdf.plugin.autotable.min.js", "./lib/zxing-reader.js", "./lib/zxing_reader.wasm"];
self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => Promise.all(SHELL.map(u => c.add(u).catch(() => {})))).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  if (url.origin !== location.origin) return;
  // La API y el panel nunca se guardan en caché (los datos se guardan en el teléfono por la app)
  if (url.pathname.includes("/api/") || url.pathname.includes("/admin")) return;
  if (url.pathname.includes("/lib/")) {
    // Librerías: caché primero (no cambian entre versiones)
    e.respondWith(caches.match(e.request).then(r => r || fetch(e.request).then(res => { const c = res.clone(); caches.open(CACHE).then(ca => ca.put(e.request, c)); return res; })));
    return;
  }
  // App: red primero para recibir actualizaciones; caché si no hay internet
  e.respondWith(fetch(e.request).then(r => { if (r.ok) { const c = r.clone(); caches.open(CACHE).then(ca => ca.put(e.request, c)); } return r; })
    .catch(() => caches.match(e.request).then(r => r || caches.match("./index.html"))));
});
