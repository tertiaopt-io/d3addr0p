/*
 * DEAD DROP service worker (ADR-004, M1 slice 5): integrity-pinned PWA shell.
 *
 * Goal: once installed, the app stops downloading fresh code from the (untrusted) origin on
 * every load. Each asset is pinned to a SHA-256. On install the SW fetches every pinned asset,
 * verifies its hash, and caches it ONLY if it matches; a single mismatch fails the install so a
 * tampered bundle is never activated. On fetch it serves cache-first. The application code the
 * manifest covers is replaced only when a new pinned manifest passes verification. The service
 * worker file ITSELF is not self-pinned (the browser may re-fetch a new sw.js from the untrusted
 * origin), so any sw.js change must be re-verified out of band against the published build hash;
 * this is the trust-on-first-use / update residual noted below.
 *
 * The hashing logic mirrors src/integrity.ts (the unit-tested source of truth). At build time
 * PINNED_ASSETS is generated from the reproducible bundle; the placeholder below is replaced by
 * the bundler. The published manifest hash is verified out of band (honest-limits point 6).
 *
 * HONEST LIMIT: this protects updates after the first install. First load is trust-on-first-use
 * and the browser/OS are the trusted base. It raises the cost of a per-target backdoor; it does
 * not reach packaged-client assurance.
 */

// Build-time generated: the cache name is UNIQUE to this pin set (a hash of the manifest), so an
// update installs into a FRESH cache and the swap is atomic at activate. A failed or interrupted
// install can never write into the cache the running worker is serving from — no mixed builds.
const CACHE = 'deaddrop-pinned-MANIFEST';

// Build-time generated: { "/index.html": "<sha256-hex>", "/app.js": "<sha256-hex>", ... }
const PINNED_ASSETS = {};

async function sha256Hex(buffer) {
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      for (const [path, expected] of Object.entries(PINNED_ASSETS)) {
        const res = await fetch(path, { cache: 'no-store' });
        if (!res.ok) {
          // Fail closed on a fetch error too, not only on a hash mismatch: an error body must never
          // reach the cache, even in the unlikely event its bytes hashed to the pinned value.
          throw new Error('fetch failed for ' + path + ': ' + res.status);
        }
        const bytes = await res.clone().arrayBuffer();
        const actual = await sha256Hex(bytes);
        if (actual !== expected.toLowerCase()) {
          // Refuse the whole install if any asset fails to match its pinned hash.
          throw new Error('integrity check failed for ' + path);
        }
        await cache.put(path, res);
      }
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      // Delete every OTHER version's cache. `stale` is non-empty only on an UPDATE (a first install has
      // no prior cache); it is the signal that a page open right now may be running assets from before
      // this worker took over.
      const names = await caches.keys();
      const stale = names.filter((n) => n !== CACHE);
      await Promise.all(stale.map((n) => caches.delete(n)));
      await self.clients.claim();
      // Recover a mismatched page automatically, but ONLY a page that could actually be mismatched. The
      // pre-versioned worker wrote updates one file at a time into a SHARED cache, so an interrupted
      // install could leave a page serving NEW app.js against OLD css; those pages (stale cache names
      // that do NOT match the versioned deaddrop-pinned-<hash> pattern) are reloaded once to recover.
      // A page served by a VERSIONED worker is always self-consistent (its whole cache was written
      // atomically), so it is NEVER force-reloaded: the app holds the master key in memory only, and a
      // forced reload on every deploy was bouncing signed-in users to the unlock screen mid-session.
      // Such pages simply keep running their version until the user's next natural reload.
      const legacy = stale.filter((n) => !/^deaddrop-pinned-[0-9a-f]{16}$/.test(n));
      if (legacy.length > 0) {
        const clients = await self.clients.matchAll({ type: 'window' });
        for (const client of clients) {
          if ('navigate' in client) {
            client.navigate(client.url).catch(() => {
              /* a client that refuses navigation just waits for its next reload */
            });
          }
        }
      }
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !(url.pathname in PINNED_ASSETS)) {
    return; // only the pinned app shell is served from cache
  }
  event.respondWith(
    (async () => {
      // Serve from THIS version's cache only (caches.match would search every cache, including a
      // newer version's mid-install one — that must never leak into a page running this version).
      const cache = await caches.open(CACHE);
      const cached = await cache.match(event.request);
      return cached || new Response('not in pinned cache', { status: 504 });
    })(),
  );
});
