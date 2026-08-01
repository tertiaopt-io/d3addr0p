// Force the browser onto the latest deployed client on entry, no matter what stale version a cached
// service worker is still serving.
//
// WHY THIS IS NEEDED. The integrity-pinned service worker (sw.js) installs each build into its own
// versioned cache and serves cache-first. The activate handler DELIBERATELY does not reload a signed-in
// page on update (a forced reload on every deploy bounced users to the unlock screen mid-session), so an
// open page keeps its already-parsed JS bundle until a NATURAL reload. On a phone that is rarely fully
// reloaded, that means it can run a build that is days old — which is exactly how a device ended up
// unable to converge with no diagnostic in its console (the console line did not exist in its old code).
//
// THE FIX. On entry (the unlock screen, before the user does anything), compare the version THIS page
// loaded against the version the origin currently advertises in /build.txt (which is never pinned, so it
// is always fetched fresh from the network). If they differ, force the service worker to fetch the new
// sw.js, wait for its new cache to activate, and reload — so the user always logs in on the latest code.
// A sessionStorage latch bounds this to one forced reload per target version, so a failed update can
// never loop.
//
// This module holds only the PURE decision logic (parsing + the reload predicate), unit-tested here. The
// browser glue (service-worker update, caches inspection, reload) lives in boot.js against these.

/** The versioned pinned-cache name pattern the deploy pipeline writes (pin-sw.mjs): a 16-hex suffix that
 * is a hash of the whole pin set, so it changes on every build whose assets changed. */
const CACHE_VERSION_RE = /deaddrop-pinned-([0-9a-f]{16})/;

/** Extract the pinned-cache version from a `/build.txt` body (its `cache: deaddrop-pinned-<hex>` line),
 * or null when the text is missing/malformed. Tolerant of surrounding lines and whitespace. */
export function parseBuildVersion(buildTxt: string | null | undefined): string | null {
  if (typeof buildTxt !== 'string') {
    return null;
  }
  const m = CACHE_VERSION_RE.exec(buildTxt);
  return m === null ? null : m[1] ?? null;
}

/** The version string out of a cache name (e.g. "deaddrop-pinned-ab12…" -> "ab12…"), or null. Used to
 * read the version THIS page is being served from out of the active caches. */
export function versionFromCacheName(name: string): string | null {
  const m = CACHE_VERSION_RE.exec(name);
  return m === null ? null : m[1] ?? null;
}

/** The version this page LOADED from, given the set of pinned caches present at boot. There is at most
 * one after a clean activate (the SW deletes stale caches), so we take the first match; null when none
 * exists yet (a first install, before any cache — nothing to be stale against). */
export function bootVersionFrom(cacheNames: readonly string[]): string | null {
  for (const n of cacheNames) {
    const v = versionFromCacheName(n);
    if (v !== null) {
      return v;
    }
  }
  return null;
}

/**
 * Whether to force an update-and-reload now. True ONLY when:
 *  - we know both the version this page loaded (`bootVersion`) and the latest advertised (`latest`), AND
 *  - they differ (this page is running older code than is deployed), AND
 *  - we have not ALREADY forced a reload targeting this same latest version this session
 *    (`alreadyTriedTarget`), so a failed update degrades to running the old build, never an infinite loop.
 *
 * Returns false whenever either version is unknown (offline, first install, no service worker), so a
 * transient failure to read the version never reloads.
 */
export function shouldForceUpdate(
  bootVersion: string | null,
  latest: string | null,
  alreadyTriedTarget: string | null,
): boolean {
  if (bootVersion === null || latest === null) {
    return false;
  }
  if (bootVersion === latest) {
    return false;
  }
  return alreadyTriedTarget !== latest;
}
