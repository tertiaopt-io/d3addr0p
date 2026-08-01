// DEAD DROP bootstrap. External (not inline) so a strict CSP needs no script-src 'unsafe-inline',
// and so the integrity-pinned service worker covers it like any other shell asset. Lives at the web
// root so its relative imports ('./dist/…', './worker.js', './wasm/…') resolve against the root.
import { mountApp, DemoController } from './dist/app.js';
import { AccountClient, httpAccountTransport } from './dist/auth.js';
import { parseBuildVersion, bootVersionFrom, shouldForceUpdate } from './dist/appversion.js';

const root = document.getElementById('app');
if (!root) {
  throw new Error('no #app');
}

// Integrity-pinned PWA shell (ADR-004): once installed, app code is served from a hash-verified
// cache instead of refetched from the origin each load. Inert until sw.js ships a populated pin set
// (the deploy build injects it), so this is a no-op in local dev.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js').catch((e) => console.warn('sw register failed', e));
  });
}

// Force the latest client on entry, no matter what stale version a cached service worker is serving.
// The SW serves cache-first and does NOT reload a signed-in page on update (that used to bounce users to
// unlock mid-session), so an open page — especially a phone that is rarely fully reloaded — can run a
// build days old. On the unlock screen, before the user does anything, compare the version this page
// LOADED against the version the origin advertises in /build.txt (never pinned, so always fetched fresh).
// If this page is older, fetch the new sw.js, wait for its cache to activate, and reload onto the latest.
// Latched in sessionStorage to at most one forced reload per target version, so a failed update can never
// loop. Best-effort: any failure (offline, no SW, no caches API) simply proceeds on the current build.
const UPDATE_TARGET_KEY = 'dd-update-target';
async function ensureLatestClient() {
  try {
    if (!('serviceWorker' in navigator) || typeof caches === 'undefined') {
      return; // no service worker / no Cache API: nothing is cached to be stale against
    }
    const bootVersion = bootVersionFrom(await caches.keys());
    let latest = null;
    try {
      // Bounded so a hung network never blocks the unlock screen (this runs before mountApp).
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 3000);
      let res;
      try {
        res = await fetch('/build.txt', { cache: 'no-store', signal: ctrl.signal });
      } finally {
        clearTimeout(timer);
      }
      if (res.ok) {
        latest = parseBuildVersion(await res.text());
      }
    } catch {
      return; // offline, blocked, or timed out: never reload on an unknown latest
    }
    let tried = null;
    try {
      tried = sessionStorage.getItem(UPDATE_TARGET_KEY);
    } catch {
      /* sessionStorage unavailable (private mode edge): treat as no prior attempt */
    }
    if (bootVersion !== null && latest !== null && bootVersion === latest) {
      // We are current: clear any stale latch so a FUTURE deploy can trigger again.
      try {
        sessionStorage.removeItem(UPDATE_TARGET_KEY);
      } catch {
        /* ignore */
      }
      return;
    }
    if (!shouldForceUpdate(bootVersion, latest, tried)) {
      return;
    }
    // Latch BEFORE reloading, so if the update does not take (the reload lands on the same old cache)
    // the next boot sees tried === latest and does not loop. If the latch cannot be PERSISTED (a
    // sandboxed context with sessionStorage disabled), we cannot guarantee the no-loop property, so we
    // must NOT force a reload — degrade to running the current build. A missed forced update is a minor
    // staleness; a reload loop bricks the site entirely.
    let latched = false;
    try {
      sessionStorage.setItem(UPDATE_TARGET_KEY, latest);
      latched = sessionStorage.getItem(UPDATE_TARGET_KEY) === latest;
    } catch {
      latched = false;
    }
    if (!latched) {
      return;
    }
    const reg = await navigator.serviceWorker.getRegistration();
    if (reg === undefined || reg === null) {
      location.reload(); // no registration yet: a plain reload re-runs registration + install
      return;
    }
    // Ask the browser to re-fetch sw.js NOW (it may not have checked since the deploy). FIRE-AND-FORGET,
    // never awaited: reg.update() can pend on a hung network, and awaiting it at the top level would
    // block mountApp behind a blank page. The bounded caches.keys() poll below is what actually waits for
    // the new version's cache to appear; a changed sw.js installs its verified pin set into that cache
    // asynchronously in the meantime.
    reg.update().catch(() => {
      /* transient; the poll + reload path does not depend on this resolving */
    });
    // Reload once the new version's cache is actually present, so the reload re-imports NEW code rather
    // than the same old cache. Poll caches.keys() for the latest version, bounded so we never hang.
    const deadline = Date.now() + 10000;
    for (;;) {
      let names = [];
      try {
        names = await caches.keys();
      } catch {
        break;
      }
      if (names.some((n) => n.indexOf(latest) !== -1) || Date.now() > deadline) {
        break;
      }
      await new Promise((r) => setTimeout(r, 300));
    }
    location.reload();
  } catch {
    /* any failure: proceed on the current build (the latch prevents a retry storm) */
  }
}
// Run the check before mounting the app, so a stale phone reloads onto the latest BEFORE the user signs
// in. Awaited so a forced reload preempts mountApp (no flash of the old UI). If it decides not to update,
// it resolves fast (one build.txt fetch) and the app mounts normally.
await ensureLatestClient();

// Gateway WebSocket: same-origin WSS in production (Apache proxies /ws to the loopback gateway); a
// direct loopback port for local dev. Override with window.DD_WS_URL if needed.
const wsUrl =
  window.DD_WS_URL ??
  (location.protocol === 'https:' ? `wss://${location.host}/ws` : `ws://${location.hostname}:8443/ws`);

// Account server (control-plane): same-origin /api in production (Apache proxies it to PHP-FPM). It
// is enabled where there is a real backend (https) and can be forced with window.DD_API_BASE (set to
// '' for same-origin, or a full base URL). When absent (local dev with no control-plane) the app
// runs local-only: register/login just open the local vault, with no server username uniqueness.
const apiBase = window.DD_API_BASE ?? (location.protocol === 'https:' ? '' : null);
const account = apiBase !== null ? new AccountClient(httpAccountTransport(apiBase)) : undefined;
// The v2 auth secret is derived with the SAME memory-hard Argon2id the vault uses, on this device, so
// the server only ever stores a fast hash of the result and a sign-in costs it microseconds instead of
// 64 MiB. Where the owning worker exists it does the derivation (wireStrongKdf below): Argon2id is a
// synchronous ~64 MiB grind, so running it here would freeze the sign-in screen and instantiate a
// SECOND wasm module on the main thread beside the worker's. This lazy main-thread path is the
// fallback for a host with no worker, where the controller already runs here anyway. Loaded lazily
// either way, so a visitor who never signs in never pays for it.
const mainThreadKdf = async (passphrase, salt) => {
  const wasm = await import('./wasm/deaddrop_crypto.js');
  await wasm.default();
  return wasm.deriveMasterKey(passphrase, salt);
};

// Point the account client's KDF at the worker when it offers one. A worker that predates the op (or
// fails the call) falls back here, and a failing KDF already degrades to the v1 auth secret, which
// the server still accepts, so a miss costs latency and never sign-in itself.
const wireStrongKdf = (controller) => {
  if (account === undefined) {
    return;
  }
  const offThread = controller?.deriveAuthKey;
  if (typeof offThread !== 'function') {
    account.useStrongKdf(mainThreadKdf);
    return;
  }
  account.useStrongKdf(async (passphrase, salt) => {
    try {
      return await offThread.call(controller, passphrase, salt);
    } catch {
      return await mainThreadKdf(passphrase, salt);
    }
  });
};
// Direct P2P file transfer (N7) + audio/video calls (P2): adapt the browser RTCPeerConnection to the
// injected factory shape. One adapter serves both: a file transfer uses the data-channel members; a
// call uses the media members (addTrack/ontrack). STUN is used only for connection setup (NAT
// discovery); it never relays the bytes or media, and there is no TURN relay, so a strict NAT can
// prevent a direct connection (disclosed in honest-limits). Each peer learns the other's IP.
const rtcFactory =
  typeof RTCPeerConnection === 'undefined'
    ? undefined
    : () => {
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        return {
          createDataChannel: (label) => pc.createDataChannel(label),
          createOffer: () => pc.createOffer(),
          createAnswer: () => pc.createAnswer(),
          setLocalDescription: (d) => pc.setLocalDescription(d),
          setRemoteDescription: (d) => pc.setRemoteDescription(d),
          addIceCandidate: (c) => pc.addIceCandidate(c),
          addTrack: (track, stream) => pc.addTrack(track, stream),
          get connectionState() {
            return pc.connectionState;
          },
          set onicecandidate(h) {
            pc.onicecandidate = h;
          },
          set ondatachannel(h) {
            pc.ondatachannel = h;
          },
          set ontrack(h) {
            pc.ontrack = h;
          },
          set onconnectionstatechange(h) {
            pc.onconnectionstatechange = h;
          },
          close: () => pc.close(),
        };
      };
// getUserMedia for calls. Audio is captured with echo cancellation / noise suppression for a clean,
// low-latency Opus stream; video is held to a modest resolution and frame rate to keep latency and
// bandwidth sane. Absent where the browser has no camera/mic API (then calls are unavailable).
const media =
  typeof navigator !== 'undefined' && navigator.mediaDevices && navigator.mediaDevices.getUserMedia
    ? ({ audio, video, facingMode }) =>
        navigator.mediaDevices.getUserMedia({
          audio: audio ? { echoCancellation: true, noiseSuppression: true, autoGainControl: true } : false,
          // facingMode is advisory ('ideal'): the QR scanner asks for the rear camera on phones, but a
          // single-camera device (laptop) still gets its one camera instead of failing.
          video: video
            ? { width: { ideal: 640 }, height: { ideal: 480 }, frameRate: { ideal: 24 }, ...(facingMode ? { facingMode: { ideal: facingMode } } : {}) }
            : false,
        })
    : undefined;
const mount = (controller, withAccounts = true) => {
  if (withAccounts) {
    wireStrongKdf(controller);
  }
  return mountApp(root, controller, { wsUrl, account: withAccounts ? account : undefined, rtcFactory, media });
};

const withTimeout = (p, ms) =>
  Promise.race([p, new Promise((_r, reject) => setTimeout(() => reject(new Error('timeout')), ms))]);

// Preferred path: the owning Web Worker (worker.js) is the SOLE writer to storage and the sole
// holder of the unlocked MSK and wasm keys, so secrets stay off the main thread and two tabs cannot
// race the stores. We construct it, then probe with ping() so a worker whose wasm failed to load
// falls back rather than leaving the UI wedged.
const tryWorker = async () => {
  if (typeof Worker === 'undefined') {
    return null;
  }
  const { WorkerController, workerTransport } = await import('./dist/workerproxy.js');
  const worker = new Worker('./worker.js', { type: 'module' });
  const controller = new WorkerController(workerTransport(worker));
  await withTimeout(controller.ping(), 8000); // wasm + Argon2id init can be slow on first load
  return controller;
};

// Fallback path: run the same real controller on the main thread (wasm Argon2id unlock +
// IndexedDB-backed channels and history). Loses the off-thread isolation but is fully functional.
const tryMainThread = async () => {
  const [{ AppControllerImpl }, idb, wasm] = await Promise.all([
    import('./dist/controller.js'),
    import('./dist/idb.js'),
    import('./wasm/deaddrop_crypto.js'),
  ]);
  await wasm.default();
  const db = await idb.openDeadDropDb();
  const deriveKek = (passphrase, salt) => Promise.resolve(wasm.deriveMasterKey(passphrase, salt));
  const identity = () => {
    const conv = new wasm.Conversation('me');
    const hex = conv.signaturePublicKeyHex();
    conv.free();
    return Promise.resolve([0, 2, 4, 6].map((i) => hex.slice(i, i + 2).toUpperCase()).join('·'));
  };
  return new AppControllerImpl(
    new idb.MskVault(db, deriveKek),
    new idb.ChannelStore(db),
    new idb.IndexedDbKeyvaultStore(db),
    undefined,
    identity,
  );
};

// worker -> main-thread -> demo. The demo keeps the shell usable on an older preview with no wasm.
(async () => {
  try {
    const fromWorker = await tryWorker();
    if (fromWorker) {
      mount(fromWorker);
      return;
    }
  } catch (err) {
    console.warn('owning worker unavailable; trying main thread', err);
  }
  try {
    mount(await tryMainThread());
  } catch (err) {
    console.warn('real backend unavailable; using demo', err);
    mount(new DemoController(), false); // demo is local-only sample data; no account server
  }
})();
